#ifndef _KCOMPAT_H
#define _KCOMPAT_H

#ifndef __LINUX_BITMAP_H
#define bitmap_zalloc(nbits, flags) vmalloc(BITS_TO_LONGS(nbits) * sizeof(unsigned long))
#define bitmap_free(b) vfree(b)
#endif

#ifndef kfree_rcu_mightsleep
#define kfree_rcu_mightsleep kfree_rcu
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 4, 0)
#define register_sysctl(_a, _b) register_sysctl_paths(net_ipt_isg_ctl_path, _b)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
#define timer_delete del_timer
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 16, 0)
#define timer_container_of from_timer
#endif
#endif
