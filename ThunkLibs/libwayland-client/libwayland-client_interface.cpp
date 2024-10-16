#include <common/GeneratorInterface.h>

#include <wayland-client.h>

template<auto>
struct fex_gen_config {
    unsigned version = 0;
};

template<typename>
struct fex_gen_type {};

template<> struct fex_gen_config<wl_proxy_destroy> : fexgen::custom_guest_entrypoint {};

template<> struct fex_gen_config<wl_display_cancel_read> {};
template<> struct fex_gen_config<wl_display_connect> {};
template<> struct fex_gen_config<wl_display_create_queue> {};
template<> struct fex_gen_config<wl_display_disconnect> {};
template<> struct fex_gen_config<wl_display_dispatch> {};
template<> struct fex_gen_config<wl_display_dispatch_pending> {};
template<> struct fex_gen_config<wl_display_dispatch_queue> {};
template<> struct fex_gen_config<wl_display_dispatch_queue_pending> {};
template<> struct fex_gen_config<wl_display_flush> {};
template<> struct fex_gen_config<wl_display_prepare_read> {};
template<> struct fex_gen_config<wl_display_prepare_read_queue> {};
template<> struct fex_gen_config<wl_display_read_events> {};
template<> struct fex_gen_config<wl_display_roundtrip> {};
template<> struct fex_gen_config<wl_display_roundtrip_queue> {};
template<> struct fex_gen_config<wl_display_get_fd> {};

template<> struct fex_gen_config<wl_event_queue_destroy> {};

template<> struct fex_gen_config<wl_proxy_add_listener> : fexgen::custom_host_impl, fexgen::custom_guest_entrypoint {};
template<> struct fex_gen_config<wl_proxy_create> {};
template<> struct fex_gen_config<wl_proxy_create_wrapper> {};
template<> struct fex_gen_config<wl_proxy_get_tag> {};
template<> struct fex_gen_config<wl_proxy_get_user_data> {};
template<> struct fex_gen_config<wl_proxy_get_version> {};
template<> struct fex_gen_config<wl_proxy_set_queue> {};
template<> struct fex_gen_config<wl_proxy_set_tag> {};
template<> struct fex_gen_config<wl_proxy_set_user_data> {};
template<> struct fex_gen_config<wl_proxy_wrapper_destroy> {};

template<> struct fex_gen_config<wl_proxy_marshal_array> {};
// wl_proxy_marshal_array_flags is only available starting from Wayland 1.19.91
#if WAYLAND_VERSION_MAJOR * 10000 + WAYLAND_VERSION_MINOR * 100 + WAYLAND_VERSION_MICRO >= 11991
template<> struct fex_gen_config<wl_proxy_marshal_array_flags> {};
#endif

// Guest notifies host about its interface. Host returns its corresponding interface pointer
wl_interface* fex_wl_exchange_interface_pointer(wl_interface*, const char* name);
template<> struct fex_gen_config<fex_wl_exchange_interface_pointer> : fexgen::custom_host_impl {};
