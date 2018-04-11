// SPDX-License-Identifier: GPL-2.0+
/*
 * Configfs interface for DT Overlay
 *
 * Copyright (C) 2013 - Pantelis Antoniou <panto@antoniou-consulting.com>
 *
 * Copyright (c) 2018 Linaro Ltd.
 * Author: Manivannan Sadhasivam <manivannan.sadhasivam@linaro.org>
 */

#include <linux/configfs.h>
#include <linux/cpu.h>
#include <linux/ctype.h>
#include <linux/file.h>
#include <linux/firmware.h>
#include <linux/limits.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/proc_fs.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/stat.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

#include "of_private.h"

struct configfs_overlay_item {
	struct config_item	item;
	const struct firmware	*fw;
	struct device_node	*overlay;
	int			ovcs_id;
	char			path[PATH_MAX];
	int			dtbo_size;
	void			*dtbo;
};

static int create_overlay(struct configfs_overlay_item *overlay, void *blob)
{
	struct device_node *dest_node, *child_node, *overlay_node;
	int ret;

	/* unflatten the overlay */
	of_fdt_unflatten_tree(blob, NULL, &overlay->overlay);
	if (overlay->overlay == NULL) {
		pr_err("%s: Failed to unflatten tree\n", __func__);
		return -EINVAL;
	}
	pr_debug("%s: Unflattened overlay\n", __func__);

	/* mark overlay as detached */
	of_node_set_flag(overlay->overlay, OF_DETACHED);

	/* perform a local resolution before checking overlay */
	ret = of_resolve_phandles(overlay->overlay);
	if (ret != 0) {
		pr_err("%s: Failed to resolve phandles\n", __func__);
		return ret;
	}
	pr_debug("%s: Phandles resolved\n", __func__);
	
	/*
	 * check for "enable-overlay" property in the base tree
	 * for target node in each overlay fragments. Return
	 * -EPERM if the property is not found for any fragments.
	 * This check is mandatory for preventing the addition of
	 * random nodes to the live tree.
	 */
	for_each_child_of_node(overlay->overlay, child_node) {
		overlay_node = of_get_child_by_name(child_node, "__overlay__");
		if (!overlay_node)
			continue;

		dest_node = find_target_node(child_node);
		if (!dest_node) {
			of_node_put(overlay->overlay);
			return -EINVAL;
		}

		if (!of_find_property(dest_node, "enable-overlay", NULL))
			return -EPERM;	
	}

	/* apply overlay */
	ret = of_overlay_apply(overlay->overlay, &overlay->ovcs_id);
	if (ret < 0) {
		pr_err("%s: Failed to apply overlay\n", __func__);
		return -EINVAL;
	}

	return 0;
}

static inline struct configfs_overlay_item *to_cfs_overlay_item(
		struct config_item *item)
{
	return item ? container_of(item, struct configfs_overlay_item, item) : NULL;
}

static ssize_t configfs_overlay_item_path_show(struct config_item *item,
		char *page)
{
	struct configfs_overlay_item *overlay = to_cfs_overlay_item(item);

	return snprintf(page, sizeof(overlay->path) - 1, "%s\n", overlay->path);
}

static ssize_t configfs_overlay_item_path_store(struct config_item *item,
		const char *page, size_t count)
{
	struct configfs_overlay_item *overlay = to_cfs_overlay_item(item);
	char *s;
	int err;

	/* do not allow changes to the existing overlay */
	if (overlay->path[0] != '\0' || overlay->dtbo_size > 0)
		return -EPERM;

	/* copy to path buffer (and make sure it's always zero terminated */
	count = snprintf(overlay->path, sizeof(overlay->path) - 1, "%s", page);
	overlay->path[sizeof(overlay->path) - 1] = '\0';

	/* strip trailing newlines */
	s = overlay->path + strlen(overlay->path);
	while (s > overlay->path && *--s == '\n')
		*s = '\0';

	pr_debug("%s: path is '%s'\n", __func__, overlay->path);

	/* request dtbo from the firmware name provided */
	err = request_firmware(&overlay->fw, overlay->path, NULL);
	if (err != 0)
		goto out_err;

	err = create_overlay(overlay, (void *)overlay->fw->data);
	if (err != 0)
		goto out_err;

	return count;

out_err:

	release_firmware(overlay->fw);
	overlay->fw = NULL;
	overlay->path[0] = '\0';
	
	return err;
}

static ssize_t configfs_overlay_item_status_show(struct config_item *item,
		char *page)
{
	struct configfs_overlay_item *overlay = to_cfs_overlay_item(item);

	return sprintf(page, "%s\n",
			overlay->ovcs_id >= 0 ? "applied" : "unapplied");
}

CONFIGFS_ATTR(configfs_overlay_item_, path);
CONFIGFS_ATTR_RO(configfs_overlay_item_, status);

static struct configfs_attribute *configfs_overlay_attrs[] = {
	&configfs_overlay_item_attr_path,
	&configfs_overlay_item_attr_status,
	NULL,
};

ssize_t configfs_overlay_item_dtbo_read(struct config_item *item,
		void *buf, size_t max_count)
{
	struct configfs_overlay_item *overlay = to_cfs_overlay_item(item);

	pr_debug("%s: buf=%p max_count=%zu\n", __func__,
			buf, max_count);

	if (overlay->dtbo == NULL)
		return 0;

	/* copy if buffer provided */
	if (buf != NULL) {
		/* the buffer must be large enough */
		if (overlay->dtbo_size > max_count)
			return -ENOSPC;

		memcpy(buf, overlay->dtbo, overlay->dtbo_size);
	}

	return overlay->dtbo_size;
}

ssize_t configfs_overlay_item_dtbo_write(struct config_item *item,
		const void *buf, size_t count)
{
	struct configfs_overlay_item *overlay = to_cfs_overlay_item(item);
	int err;

	/* do not allow changes to the existing overlay */
	if (overlay->path[0] != '\0' || overlay->dtbo_size > 0)
		return -EPERM;

	/* copy the dtbo */
	overlay->dtbo = kmemdup(buf, count, GFP_KERNEL);
	if (overlay->dtbo == NULL)
		return -ENOMEM;

	overlay->dtbo_size = count;

	err = create_overlay(overlay, overlay->dtbo);
	if (err != 0)
		goto out_err;

	return count;

out_err:
	kfree(overlay->dtbo);
	overlay->dtbo = NULL;
	overlay->dtbo_size = 0;

	return err;
}

CONFIGFS_BIN_ATTR(configfs_overlay_item_, dtbo, NULL, SZ_1M);

static struct configfs_bin_attribute *configfs_overlay_bin_attrs[] = {
	&configfs_overlay_item_attr_dtbo,
	NULL,
};

static void configfs_overlay_release(struct config_item *item)
{
	struct configfs_overlay_item *overlay = to_cfs_overlay_item(item);

	if (overlay->ovcs_id >= 0)
		of_overlay_remove(&overlay->ovcs_id);
	if (overlay->fw)
		release_firmware(overlay->fw);
	/* kfree with NULL is safe */
	kfree(overlay->dtbo);
	kfree(overlay);
}

static struct configfs_item_operations configfs_overlay_item_ops = {
	.release	= configfs_overlay_release,
};

static struct config_item_type configfs_overlay_type = {
	.ct_item_ops	= &configfs_overlay_item_ops,
	.ct_attrs	= configfs_overlay_attrs,
	.ct_bin_attrs	= configfs_overlay_bin_attrs,
	.ct_owner	= THIS_MODULE,
};

static struct config_item *configfs_overlay_group_make_item(
		struct config_group *group, const char *name)
{
	struct configfs_overlay_item *overlay;

	overlay = kzalloc(sizeof(*overlay), GFP_KERNEL);
	if (!overlay)
		return ERR_PTR(-ENOMEM);
	
	overlay->ovcs_id = -1;
	config_item_init_type_name(&overlay->item, name, &configfs_overlay_type);

	return &overlay->item;
}

static void configfs_overlay_group_drop_item(struct config_group *group,
		struct config_item *item)
{
	struct configfs_overlay_item *overlay = to_cfs_overlay_item(item);

	config_item_put(&overlay->item);
}

static struct configfs_group_operations of_configfs_overlay_ops = {
	.make_item	= configfs_overlay_group_make_item,
	.drop_item	= configfs_overlay_group_drop_item,
};

static const struct config_item_type of_configfs_overlay_type = {
	.ct_group_ops   = &of_configfs_overlay_ops,
	.ct_owner       = THIS_MODULE,
};

static const struct config_item_type of_configfs_type = {
	.ct_owner       = THIS_MODULE,
};

struct config_group of_configfs_overlay_group;

static struct configfs_subsystem of_configfs_subsys = {
	.su_group = {
		.cg_item = {
			.ci_namebuf = "device-tree",
			.ci_type = &of_configfs_type,
		},
	},
	.su_mutex = __MUTEX_INITIALIZER(of_configfs_subsys.su_mutex),
};

static int __init of_configfs_init(void)
{
	int ret;

	config_group_init(&of_configfs_subsys.su_group);
	config_group_init_type_name(&of_configfs_overlay_group, "overlays",
			&of_configfs_overlay_type);
	configfs_add_default_group(&of_configfs_overlay_group,
			&of_configfs_subsys.su_group);

	ret = configfs_register_subsystem(&of_configfs_subsys);
	if (ret != 0) {
		pr_err("%s: Failed to register subsys\n", __func__);
		return ret;
	}
	
	return ret;
}
late_initcall(of_configfs_init);
