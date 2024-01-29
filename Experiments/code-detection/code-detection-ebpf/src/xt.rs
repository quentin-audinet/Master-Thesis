use aya_bpf::{bindings::__IncompleteArrayField, cty::c_char};

use crate::vmlinux::{list_head, module, sk_buff};

pub type __u16 = ::aya_bpf::cty::c_ushort;
pub type __u8 = ::aya_bpf::cty::c_uchar;
pub type __c_char = ::aya_bpf::cty::uint8_t;
pub type __uint = ::aya_bpf::cty::c_uint;
pub type __ushort = ::aya_bpf::cty::c_ushort;

const XT_EXTENSION_MAXNAMELEN: usize = 29;
const XT_FUNCTION_MAXNAMELEN: usize = 30;

/*

xt_entry_target structure

struct xt_entry_target {
	union {
		struct {
			__u16 target_size;

			/* Used by userspace */
			char name[XT_EXTENSION_MAXNAMELEN];
			__u8 revision;
		} user;
		struct {
			__u16 target_size;

			/* Used inside the kernel */
			struct xt_target *target;
		} kernel;

		/* Total length */
		__u16 target_size;
	} u;

	unsigned char data[0];
};
*/
#[repr(C)]
pub struct xt_entry_target {
    pub u: xt_entry_target_u,
    pub data: __IncompleteArrayField<::aya_bpf::cty::c_char>,// TODO unsigned char data[0];
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union xt_entry_target_u {
    pub user: xt_entry_target_u_user,
    pub kernel: xt_entry_target_u_kernel,
    pub target_size: __u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct xt_entry_target_u_user {
    pub target_size: __u16,
    pub name: [__c_char; XT_EXTENSION_MAXNAMELEN],
    pub revision: __u8,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct xt_entry_target_u_kernel {
    pub target_size: __u16,
    pub target: *mut xt_target,
}


/*
compat_xt_entry_target structure

struct compat_xt_entry_target {
	union {
		struct {
			u_int16_t target_size;
			char name[XT_FUNCTION_MAXNAMELEN - 1];
			u_int8_t revision;
		} user;
		struct {
			u_int16_t target_size;
			compat_uptr_t target;
		} kernel;
		u_int16_t target_size;
	} u;
	unsigned char data[0];
};
*/

#[repr(C)]
pub struct compat_xt_entry_target {
    pub u: compat_xt_entry_target_u,
    // TODO unsigned char data[0];
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union compat_xt_entry_target_u {
    pub user: compat_xt_entry_target_u_user,
    pub kernel: compat_xt_entry_target_u_kernel,
    pub target_size: __u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct compat_xt_entry_target_u_user {
    pub target_size: __u16,
    pub name: [__c_char; XT_FUNCTION_MAXNAMELEN-1],
    pub revision: __u8,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct compat_xt_entry_target_u_kernel {
    pub target_size: __u16,
    pub target: *mut xt_target,
}






/*
xt_target structure

struct xt_target {
	struct list_head list;

	const char name[XT_EXTENSION_MAXNAMELEN];
	u_int8_t revision;

	/* Returns verdict. Argument order changed since 2.6.9, as this
	   must now handle non-linear skbs, using skb_copy_bits and
	   skb_ip_make_writable. */
	unsigned int (*target)(struct sk_buff *skb,
			       const struct xt_action_param *);

	/* Called when user tries to insert an entry of this type:
           hook_mask is a bitmask of hooks from which it can be
           called. */
	/* Should return 0 on success or an error code otherwise (-Exxxx). */
	int (*checkentry)(const struct xt_tgchk_param *);

	/* Called when entry of this type deleted. */
	void (*destroy)(const struct xt_tgdtor_param *);
#ifdef CONFIG_COMPAT
	/* Called when userspace align differs from kernel space one */
	void (*compat_from_user)(void *dst, const void *src);
	int (*compat_to_user)(void __user *dst, const void *src);
#endif
	/* Set this to THIS_MODULE if you are a module, otherwise NULL */
	struct module *me;

	const char *table;
	unsigned int targetsize;
	unsigned int usersize;
#ifdef CONFIG_COMPAT
	unsigned int compatsize;
#endif
	unsigned int hooks;
	unsigned short proto;

	unsigned short family;
};
*/
#[repr(C)]
pub struct xt_target {
    pub list_head: list_head,
	pub name: [__c_char; XT_EXTENSION_MAXNAMELEN],
	pub revision: __u8,
	pub target: ::core::option::Option<
		unsafe extern "C" fn(arg1: *mut sk_buff, arg2: *mut xt_action_param) -> ::aya_bpf::cty::c_uint
	>,
	pub checkentry: ::core::option::Option<
		unsafe extern "C" fn(arg1: *mut xt_tgchk_param) -> ::aya_bpf::cty::c_int
	>,
	pub destroy: ::core::option::Option<unsafe extern "C" fn(arg1: *mut xt_tgdtor_param)>,
	pub compat_from_user: ::core::option::Option<unsafe extern "C" fn(arg1: ::aya_bpf::cty::c_void, arg2: ::aya_bpf::cty::c_void)>,
	pub compat_to_user: ::core::option::Option<unsafe extern "C" fn(arg1: ::aya_bpf::cty::c_void, arg2: ::aya_bpf::cty::c_void) -> ::aya_bpf::cty::c_int>,
	pub me: *mut module,
	pub table: *mut __c_char,
	pub targetsize: __uint,
	pub usersize: __uint,
	pub compatsize: __uint,
	pub hooks: __uint,
	pub proto: __ushort,
	pub family: __ushort,

}


#[repr(C)]
pub struct xt_action_param {

}


#[repr(C)]
pub struct xt_tgchk_param {

}


#[repr(C)]
pub struct xt_tgdtor_param {

}