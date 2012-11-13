/*
 * drivers/cpufreq/cpufreq_interactivex.c
 *
 * Copyright (C) 2010 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Author: Mike Chan (mike@android.com)
 * Modified for early suspend support and hotplugging by imoseyon (imoseyon@gmail.com)
 *   interactiveX V2
 *
 */

#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/cpufreq.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/tick.h>
#include <linux/time.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/kthread.h>
#include <linux/mutex.h>
#include <linux/earlysuspend.h>

#include <asm/cputime.h>

static atomic_t active_count = ATOMIC_INIT(0);

struct cpufreq_interactivex_cpuinfo {
	struct timer_list cpu_timer;
	int timer_idlecancel;
	u64 time_in_idle;
	u64 time_in_idle_timestamp;
	u64 target_set_time;
	u64 target_set_time_in_idle;
	struct cpufreq_policy *policy;
	struct cpufreq_frequency_table *freq_table;
	unsigned int target_freq;
	int governor_enabled;
};

static DEFINE_PER_CPU(struct cpufreq_interactivex_cpuinfo, cpuinfo);

/* realtime thread handles frequency scaling */
static struct task_struct *speedchange_task;
static cpumask_t speedchange_cpumask;
static spinlock_t speedchange_cpumask_lock;

// used for suspend code
static unsigned int enabled = 0;
static unsigned int suspendfreq = 576000;
static unsigned int registration = 0;

/* Hi speed to bump to from lo speed when load burst (default max) */
static unsigned int hispeed_freq;

/* Go to hi speed when CPU load at or above this value. */
#define DEFAULT_GO_HISPEED_LOAD 85
static unsigned long go_hispeed_load;

/*
 * The minimum amount of time to spend at a frequency before we can ramp down.
 */
#define DEFAULT_MIN_SAMPLE_TIME (30 * USEC_PER_MSEC)
static unsigned long min_sample_time;

/*
 * The sample rate of the timer used to increase frequency
 */
#define DEFAULT_TIMER_RATE 20 * USEC_PER_MSEC
static unsigned long timer_rate;

static bool governidle;
module_param(governidle, bool, S_IWUSR | S_IRUGO);
MODULE_PARM_DESC(governidle,
	"Set to 1 to wake up CPUs from idle to reduce speed (default 0)");


static int cpufreq_governor_interactivex(struct cpufreq_policy *policy,
		unsigned int event);

#ifndef CONFIG_CPU_FREQ_DEFAULT_GOV_INTERACTIVEX
static
#endif
struct cpufreq_governor cpufreq_gov_interactivex = {
	.name = "interactivex",
	.governor = cpufreq_governor_interactivex,
	.max_transition_latency = 10000000,
	.owner = THIS_MODULE,
};

static void cpufreq_interactivex_timer_resched(
	struct cpufreq_interactivex_cpuinfo *pcpu)
{
	mod_timer_pinned(&pcpu->cpu_timer,
			 jiffies + usecs_to_jiffies(timer_rate));
	pcpu->time_in_idle =
		get_cpu_idle_time_us(smp_processor_id(),
				     &pcpu->time_in_idle_timestamp);
}

static void cpufreq_interactivex_timer(unsigned long data)
{
	u64 now;
	unsigned int delta_idle;
	unsigned int delta_time;
	int cpu_load;
	int load_since_change;
	struct cpufreq_interactivex_cpuinfo *pcpu =
		&per_cpu(cpuinfo, data);
	u64 now_idle;
	unsigned int new_freq;
	unsigned int index;
	unsigned long flags;

	smp_rmb();

	if (!pcpu->governor_enabled)
		goto exit;

	now_idle = get_cpu_idle_time_us(data, &now);
	delta_idle = (unsigned int)(now_idle - pcpu->time_in_idle);
	delta_time = (unsigned int)(now - pcpu->time_in_idle_timestamp);

	/*
	 * If timer ran less than 1ms after short-term sample started, retry.
	 */
	if (delta_time < 1000)
		goto rearm;

	if (delta_idle > delta_time)
		cpu_load = 0;
	else
		cpu_load = 100 * (delta_time - delta_idle) / delta_time;

	delta_idle = (unsigned int)(now_idle - pcpu->target_set_time_in_idle);
	delta_time = (unsigned int)(now - pcpu->target_set_time);

	if ((delta_time == 0) || (delta_idle > delta_time))
		load_since_change = 0;
	else
		load_since_change =
			100 * (delta_time - delta_idle) / delta_time;

	/*
	 * Choose greater of short-term load (since last idle timer
	 * started or timer function re-armed itself) or long-term load
	 * (since last frequency change).
	 */
	if (load_since_change > cpu_load)
		cpu_load = load_since_change;

	if (cpu_load >= go_hispeed_load) {
		if (pcpu->target_freq < hispeed_freq &&
		  hispeed_freq < pcpu->policy->max) {
			new_freq = hispeed_freq;
		} else {
                        new_freq = pcpu->policy->max * cpu_load / 100;

                        if (new_freq < hispeed_freq)
                                new_freq = hispeed_freq;
		}
	} else {
		new_freq = hispeed_freq * cpu_load / 100;
	}

	if (cpufreq_frequency_table_target(pcpu->policy, pcpu->freq_table,
					   new_freq, CPUFREQ_RELATION_H,
					   &index)) {
		pr_warn_once("timer %d: cpufreq_frequency_table_target error\n",
			     (int) data);
		goto rearm;
	}

	new_freq = pcpu->freq_table[index].frequency;

	/*
	 * Do not scale down unless we have been at this frequency for the
	 * minimum sample time.
	 */
	if (new_freq < pcpu->target_freq) {
		if (now - pcpu->target_set_time < min_sample_time)
			goto rearm;
	}

        if (pcpu->target_freq == new_freq) { 
		goto rearm_if_notmax;
	}

        pcpu->target_set_time_in_idle = now_idle;
        pcpu->target_set_time = now;

	pcpu->target_freq = new_freq;
	spin_lock_irqsave(&speedchange_cpumask_lock, flags);
	cpumask_set_cpu(data, &speedchange_cpumask);
	spin_unlock_irqrestore(&speedchange_cpumask_lock, flags);
	wake_up_process(speedchange_task);

rearm_if_notmax:
	/*
	 * Already set max speed and don't see a need to change that,
	 * wait until next idle to re-evaluate, don't need timer.
	 */
	if (pcpu->target_freq == pcpu->policy->max)
		goto exit;

rearm:
	if (!timer_pending(&pcpu->cpu_timer)) {
		/*
		 * If governing speed in idle and already at min, cancel the
		 * timer if that CPU goes idle.  We don't need to re-evaluate
		 * speed until the next idle exit.
		 */
		if (governidle && pcpu->target_freq == pcpu->policy->min)
			pcpu->timer_idlecancel = 1;

		cpufreq_interactivex_timer_resched(pcpu);
	}

exit:
	return;
}

static void cpufreq_interactivex_idle_start(void)
{
	struct cpufreq_interactivex_cpuinfo *pcpu =
		&per_cpu(cpuinfo, smp_processor_id());
	int pending;

	if (!pcpu->governor_enabled)
		return;

	pending = timer_pending(&pcpu->cpu_timer);

	if (pcpu->target_freq != pcpu->policy->min) {
		/*
		 * Entering idle while not at lowest speed.  On some
		 * platforms this can hold the other CPU(s) at that speed
		 * even though the CPU is idle. Set a timer to re-evaluate
		 * speed so this idle CPU doesn't hold the other CPUs above
		 * min indefinitely.  This should probably be a quirk of
		 * the CPUFreq driver.
		 */
		if (!pending) {
			pcpu->timer_idlecancel = 0;
			cpufreq_interactivex_timer_resched(pcpu);
		}
	} else if (governidle) {
		/*
		 * If at min speed and entering idle after load has
		 * already been evaluated, and a timer has been set just in
		 * case the CPU suddenly goes busy, cancel that timer.  The
		 * CPU didn't go busy; we'll recheck things upon idle exit.
		 */
		if (pending && pcpu->timer_idlecancel) {
			del_timer(&pcpu->cpu_timer);
		}
	}

}

static void cpufreq_interactivex_idle_end(void)
{
	struct cpufreq_interactivex_cpuinfo *pcpu =
		&per_cpu(cpuinfo, smp_processor_id());

	if (!pcpu->governor_enabled)
		return;

	/* Arm the timer for 1-2 ticks later if not already. */
	if (!timer_pending(&pcpu->cpu_timer)) {
		pcpu->timer_idlecancel = 0;
		cpufreq_interactivex_timer_resched(pcpu);
	} else if (!governidle &&
		  time_after_eq(jiffies, pcpu->cpu_timer.expires)) {
		del_timer(&pcpu->cpu_timer);
		cpufreq_interactivex_timer(smp_processor_id());
	}
}

static int cpufreq_interactivex_speedchange_task(void *data)
{
	unsigned int cpu;
	cpumask_t tmp_mask;
	unsigned long flags;
	struct cpufreq_interactivex_cpuinfo *pcpu;

	while (1) {
		set_current_state(TASK_INTERRUPTIBLE);
		spin_lock_irqsave(&speedchange_cpumask_lock, flags);

		if (cpumask_empty(&speedchange_cpumask)) {
			spin_unlock_irqrestore(&speedchange_cpumask_lock,
					       flags);
			schedule();

			if (kthread_should_stop())
				break;

			spin_lock_irqsave(&speedchange_cpumask_lock, flags);
		}

		set_current_state(TASK_RUNNING);
		tmp_mask = speedchange_cpumask;
		cpumask_clear(&speedchange_cpumask);
		spin_unlock_irqrestore(&speedchange_cpumask_lock, flags);

		for_each_cpu(cpu, &tmp_mask) {
			unsigned int j;
			unsigned int max_freq = 0;

			pcpu = &per_cpu(cpuinfo, cpu);
			smp_rmb();

			if (!pcpu->governor_enabled)
				continue;

			for_each_cpu(j, pcpu->policy->cpus) {
				struct cpufreq_interactivex_cpuinfo *pjcpu =
					&per_cpu(cpuinfo, j);

				if (pjcpu->target_freq > max_freq)
					max_freq = pjcpu->target_freq;
			}

			if (max_freq != pcpu->policy->cur)
				__cpufreq_driver_target(pcpu->policy,
							max_freq,
							CPUFREQ_RELATION_H);
		}
	}

	return 0;
}

static ssize_t show_hispeed_freq(struct kobject *kobj,
				 struct attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", hispeed_freq);
}

static ssize_t store_hispeed_freq(struct kobject *kobj,
				  struct attribute *attr, const char *buf,
				  size_t count)
{
	int ret;
	long unsigned int val;

	ret = strict_strtoul(buf, 0, &val);
	if (ret < 0)
		return ret;
	hispeed_freq = val;
	return count;
}

static struct global_attr hispeed_freq_attr = __ATTR(hispeed_freq, 0644,
		show_hispeed_freq, store_hispeed_freq);


static ssize_t show_go_hispeed_load(struct kobject *kobj,
				     struct attribute *attr, char *buf)
{
	return sprintf(buf, "%lu\n", go_hispeed_load);
}

static ssize_t store_go_hispeed_load(struct kobject *kobj,
			struct attribute *attr, const char *buf, size_t count)
{
	int ret;
	unsigned long val;

	ret = strict_strtoul(buf, 0, &val);
	if (ret < 0)
		return ret;
	go_hispeed_load = val;
	return count;
}

static struct global_attr go_hispeed_load_attr = __ATTR(go_hispeed_load, 0644,
		show_go_hispeed_load, store_go_hispeed_load);

static ssize_t show_min_sample_time(struct kobject *kobj,
				struct attribute *attr, char *buf)
{
	return sprintf(buf, "%lu\n", min_sample_time);
}

static ssize_t store_min_sample_time(struct kobject *kobj,
			struct attribute *attr, const char *buf, size_t count)
{
	int ret;
	unsigned long val;

	ret = strict_strtoul(buf, 0, &val);
	if (ret < 0)
		return ret;
	min_sample_time = val;
	return count;
}

static struct global_attr min_sample_time_attr = __ATTR(min_sample_time, 0644,
		show_min_sample_time, store_min_sample_time);

static ssize_t show_timer_rate(struct kobject *kobj,
			struct attribute *attr, char *buf)
{
	return sprintf(buf, "%lu\n", timer_rate);
}

static ssize_t store_timer_rate(struct kobject *kobj,
			struct attribute *attr, const char *buf, size_t count)
{
	int ret;
	unsigned long val;

	ret = strict_strtoul(buf, 0, &val);
	if (ret < 0)
		return ret;
	timer_rate = val;
	return count;
}

static struct global_attr timer_rate_attr = __ATTR(timer_rate, 0644,
		show_timer_rate, store_timer_rate);

static struct attribute *interactivex_attributes[] = {
	&hispeed_freq_attr.attr,
	&go_hispeed_load_attr.attr,
	&min_sample_time_attr.attr,
	&timer_rate_attr.attr,
	NULL,
};

static struct attribute_group interactivex_attr_group = {
	.attrs = interactivex_attributes,
	.name = "interactivex",
};

static void interactivex_suspend(int suspend)
{
        unsigned int cpu;
        cpumask_t tmp_mask;
        struct cpufreq_interactivex_cpuinfo *pcpu;

        if (!enabled) return;
	  if (!suspend) {
		for_each_cpu(cpu, &tmp_mask) {
		  pcpu = &per_cpu(cpuinfo, cpu);
		  smp_rmb();
		  if (!pcpu->governor_enabled)
		    continue;
		  __cpufreq_driver_target(pcpu->policy, hispeed_freq, CPUFREQ_RELATION_L);
		}
	  } else {
		for_each_cpu(cpu, &tmp_mask) {
		  pcpu = &per_cpu(cpuinfo, cpu);
		  smp_rmb();
		  if (!pcpu->governor_enabled)
		    continue;
		  __cpufreq_driver_target(pcpu->policy, suspendfreq, CPUFREQ_RELATION_H);
		}
	  }
}

static void interactivex_early_suspend(struct early_suspend *handler) {
     if (!registration) interactivex_suspend(1);
}

static void interactivex_late_resume(struct early_suspend *handler) {
     interactivex_suspend(0);
}

static struct early_suspend interactivex_power_suspend = {
        .suspend = interactivex_early_suspend,
        .resume = interactivex_late_resume,
        .level = EARLY_SUSPEND_LEVEL_DISABLE_FB + 1,
};

static int cpufreq_interactivex_idle_notifier(struct notifier_block *nb,
                                             unsigned long val,
                                             void *data)
{
        switch (val) {
        case IDLE_START:
                cpufreq_interactivex_idle_start();
                break;
        case IDLE_END:
                cpufreq_interactivex_idle_end();
                break;
        }

	return 0;
}

static struct notifier_block cpufreq_interactivex_idle_nb = {
        .notifier_call = cpufreq_interactivex_idle_notifier,
};

static int cpufreq_governor_interactivex(struct cpufreq_policy *policy,
		unsigned int event)
{
	int rc;
	unsigned int j;
	struct cpufreq_interactivex_cpuinfo *pcpu;
	struct cpufreq_frequency_table *freq_table;

	switch (event) {
	case CPUFREQ_GOV_START:
		if (!cpu_online(policy->cpu))
			return -EINVAL;

		freq_table =
			cpufreq_frequency_get_table(policy->cpu);
		if (!hispeed_freq)
			hispeed_freq = policy->max;

		for_each_cpu(j, policy->cpus) {
			pcpu = &per_cpu(cpuinfo, j);
			pcpu->policy = policy;
			pcpu->target_freq = policy->cur;
			pcpu->freq_table = freq_table;
			pcpu->target_set_time_in_idle =
				get_cpu_idle_time_us(j,
					     &pcpu->target_set_time);
			pcpu->governor_enabled = 1;
			smp_wmb();
			pcpu->cpu_timer.expires =
				jiffies + usecs_to_jiffies(timer_rate);
			add_timer_on(&pcpu->cpu_timer, j);
		}

		/*
		 * Do not register the idle hook and create sysfs
		 * entries if we have already done so.
		 */
		if (atomic_inc_return(&active_count) > 1)
			return 0;

		rc = sysfs_create_group(cpufreq_global_kobject,
				&interactivex_attr_group);
		if (rc)
			return rc;

		enabled = 1;
		registration = 1;
                register_early_suspend(&interactivex_power_suspend);
		registration = 0;
		idle_notifier_register(&cpufreq_interactivex_idle_nb);
                pr_info("[imoseyon] interactivex start\n");
		break;

	case CPUFREQ_GOV_STOP:
		for_each_cpu(j, policy->cpus) {
			pcpu = &per_cpu(cpuinfo, j);
			pcpu->governor_enabled = 0;
			smp_wmb();
			del_timer_sync(&pcpu->cpu_timer);
		}

		if (atomic_dec_return(&active_count) > 0)
			return 0;

		idle_notifier_unregister(&cpufreq_interactivex_idle_nb);
		sysfs_remove_group(cpufreq_global_kobject,
				&interactivex_attr_group);

		enabled = 0;
                unregister_early_suspend(&interactivex_power_suspend);
                pr_info("[imoseyon] interactivex inactive\n");
		break;

	case CPUFREQ_GOV_LIMITS:
		if (policy->max < policy->cur)
			__cpufreq_driver_target(policy,
					policy->max, CPUFREQ_RELATION_H);
		else if (policy->min > policy->cur)
			__cpufreq_driver_target(policy,
					policy->min, CPUFREQ_RELATION_L);
		break;
	}
	return 0;
}

static int __init cpufreq_interactivex_init(void)
{
	unsigned int i;
	struct cpufreq_interactivex_cpuinfo *pcpu;
	struct sched_param param = { .sched_priority = MAX_RT_PRIO-1 };

	go_hispeed_load = DEFAULT_GO_HISPEED_LOAD;
	min_sample_time = DEFAULT_MIN_SAMPLE_TIME;
	timer_rate = DEFAULT_TIMER_RATE;

	/* Initalize per-cpu timers */
	for_each_possible_cpu(i) {
		pcpu = &per_cpu(cpuinfo, i);
		if (governidle)
			init_timer(&pcpu->cpu_timer);
		else
			init_timer_deferrable(&pcpu->cpu_timer);
		pcpu->cpu_timer.function = cpufreq_interactivex_timer;
		pcpu->cpu_timer.data = i;
	}

	spin_lock_init(&speedchange_cpumask_lock);
	speedchange_task =
		kthread_create(cpufreq_interactivex_speedchange_task, NULL,
				"cfinteractivex");
	if (IS_ERR(speedchange_task))
		return PTR_ERR(speedchange_task);

	sched_setscheduler_nocheck(speedchange_task, SCHED_FIFO, &param);
	get_task_struct(speedchange_task);

	/* NB: wake up so the thread does not look hung to the freezer */
	wake_up_process(speedchange_task);

	return cpufreq_register_governor(&cpufreq_gov_interactivex);
}

#ifdef CONFIG_CPU_FREQ_DEFAULT_GOV_INTERACTIVEX
fs_initcall(cpufreq_interactivex_init);
#else
module_init(cpufreq_interactivex_init);
#endif

static void __exit cpufreq_interactivex_exit(void)
{
	cpufreq_unregister_governor(&cpufreq_gov_interactivex);
	kthread_stop(speedchange_task);
	put_task_struct(speedchange_task);
}

module_exit(cpufreq_interactivex_exit);

MODULE_AUTHOR("Mike Chan <mike@android.com>");
MODULE_DESCRIPTION("'cpufreq_interactive' - A cpufreq governor for "
	"Latency sensitive workloads");
MODULE_LICENSE("GPL");
