/*
 * cm_support.c
 *
 * Copyright (C) 2012 Brandon Berhent <bbedward@gmail.com>
 *
 * Set a flag to make the source compatible with CyanogenMOD
 */

#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/cm_support.h>

struct kobject *cmsupport_kobj;
EXPORT_SYMBOL(cmsupport_kobj);

#ifdef CONFIG_FOR_CYANOGENMOD
int sysctl_cm_support = 1;
#else
int sysctl_cm_support = 0;
#endif

static ssize_t cl_settings_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int var;

	if (strcmp(attr->attr.name, "cm_support") == 0) {
		var = sysctl_cm_support;
	} else {
		return 0;
	}

	return sprintf(buf, "%d\n", var);
}

static ssize_t cl_settings_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int var;

	sscanf(buf, "%du", &var);

	if (var > 1) var = 1;
	else if (var < 0) var = 0;

	if (strcmp(attr->attr.name, "cm_support") == 0) {
		sysctl_cm_support = var;
	}

	return count;
}

static struct kobj_attribute cl_cm_support =
	__ATTR(cm_support, 0666, cl_settings_show,
		cl_settings_store);

static struct attribute *cm_support_attrs[] = {
	&cl_cm_support.attr, NULL,
};

static struct attribute_group cm_support_option_group = {
	.attrs = cm_support_attrs,
};

int init_cm_sysfs_interface(void)
{
	int ret;
	/* Create /sys/kernel/cmsupport/ */
	cmsupport_kobj = kobject_create_and_add("cm_support", kernel_kobj);
	if (cmsupport_kobj == NULL) {
		printk(KERN_ERR "cm_support: subsystem_register failed.\n");
		return -ENOMEM;
	} else {
		/* Add cm_support */
		ret = sysfs_create_group(cmsupport_kobj, &cm_support_option_group);
		printk(KERN_INFO "cm_support: sysfs interface initiated.\n");
	}

	return ret;
}

void cleanup_cm_sysfs_interface(void)
{
	kobject_put(cmsupport_kobj);
}

static int cm_support_sysfs_init(void)
{
	int ret;

	ret = init_cm_sysfs_interface();
	if (ret)
		goto out_error;

	return 0;

out_error:
	return ret;
}

static void cm_support_sysfs_exit(void)
{
	cleanup_cm_sysfs_interface();
}

module_init(cm_support_sysfs_init);
module_exit(cm_support_sysfs_exit);
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Brandon Berhent <bbedward@gmail.com>");

