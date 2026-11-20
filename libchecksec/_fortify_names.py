"""Frozen glibc fortification names from the GNU C Library manual.

https://sourceware.org/glibc/manual/latest/html_node/Source-Fortification.html
Retrieved 2026-11-20. Recognizes canonical __name_chk, documented long-double
compatibility aliases, and __fdelt_chk.
https://codebrowser.dev/glibc/glibc/sysdeps/ieee754/ldbl-opt/nldbl-compat.c.html
"""

# FD_* macros share the explicitly documented __fdelt_chk implementation.
FORTIFIED_FUNCTIONS = frozenset(
    """
asprintf confstr dprintf explicit_bzero fgets fgets_unlocked fgetws fgetws_unlocked
fprintf fread fread_unlocked fwprintf getcwd getdomainname getgroups gethostname
getlogin_r gets getwd inet_ntop inet_pton longjmp mbsnrtowcs mbsrtowcs mbstowcs
memcpy memmove mempcpy memset memset_explicit mq_open obstack_printf obstack_vprintf
open open64 openat openat64 poll ppoll64 ppoll pread64 pread printf ptsname_r read
readlinkat readlink realpath recv recvfrom snprintf sprintf stpcpy stpncpy strcat strcpy
strlcat strlcpy strncat strncpy swprintf syslog ttyname_r vasprintf vdprintf vfprintf
vfwprintf vprintf vsnprintf vsprintf vswprintf vsyslog vwprintf wcpcpy wcpncpy wcrtomb
wcscat wcscpy wcslcat wcslcpy wcsncat wcsncpy wcsnrtombs wcsrtombs wcstombs wctomb
wmemcpy wmemmove wmempcpy wmemset wprintf
""".split()
)
# The open families use _2 replacements, outside the checked-name rule.
OPEN_FAMILY = frozenset({"open", "open64", "openat", "openat64", "mq_open"})
CHECKED_TO_BASE = {f"__{name}_chk": name for name in FORTIFIED_FUNCTIONS - OPEN_FAMILY}
CHECKED_TO_BASE["__fdelt_chk"] = "fdelt"

# glibc defines these long-double compatibility functions with checked aliases.
NLDBL_FUNCTIONS = frozenset(
    "fprintf fwprintf printf snprintf sprintf swprintf vfprintf vfwprintf vprintf "
    "vsnprintf vsprintf vswprintf vwprintf wprintf vasprintf asprintf vdprintf dprintf "
    "obstack_vprintf obstack_printf syslog vsyslog".split()
)
CHECKED_TO_BASE.update({f"__nldbl___{name}_chk": f"__nldbl_{name}" for name in NLDBL_FUNCTIONS})
