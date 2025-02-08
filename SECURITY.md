# Security Report

## Última Actualización
`08/02/2025`

## Vulnerabilidades Detectadas
| Severidad  | Tipo          | Descripción                           | Recurso Afectado          |
|------------|---------------|---------------------------------------|---------------------------|
| LOW | CVE-2011-3374 | It was found that apt-key in apt, all versions, do not correctly valid ... | apt |
| LOW | TEMP-0841856-B18BAF | [Privilege escalation possible to other user than root] | bash |
| LOW | CVE-2017-13716 | binutils: Memory leak with the C++ symbol demangler routine in libiberty | binutils |
| LOW | CVE-2018-20673 | libiberty: Integer overflow in demangle_template() function | binutils |
| LOW | CVE-2018-20712 | libiberty: heap-based buffer over-read in d_expression_1 | binutils |
| LOW | CVE-2018-9996 | binutils: Stack-overflow in libiberty/cplus-dem.c causes crash | binutils |
| LOW | CVE-2021-32256 | binutils: stack-overflow issue in demangle_type in rust-demangle.c. | binutils |
| LOW | CVE-2023-1972 | binutils: Illegal memory access when accessing a zer0-lengthverdef table | binutils |
| LOW | CVE-2024-53589 | binutils: objdump: buffer Overflow in the BFD library's handling of tekhex format files | binutils |
| LOW | CVE-2024-57360 | binutils: nm: potential segmentation fault when displaying symbols without version info | binutils |
| LOW | CVE-2025-0840 | binutils: GNU Binutils objdump.c disassemble_bytes stack-based overflow | binutils |
| LOW | CVE-2017-13716 | binutils: Memory leak with the C++ symbol demangler routine in libiberty | binutils-common |
| LOW | CVE-2018-20673 | libiberty: Integer overflow in demangle_template() function | binutils-common |
| LOW | CVE-2018-20712 | libiberty: heap-based buffer over-read in d_expression_1 | binutils-common |
| LOW | CVE-2018-9996 | binutils: Stack-overflow in libiberty/cplus-dem.c causes crash | binutils-common |
| LOW | CVE-2021-32256 | binutils: stack-overflow issue in demangle_type in rust-demangle.c. | binutils-common |
| LOW | CVE-2023-1972 | binutils: Illegal memory access when accessing a zer0-lengthverdef table | binutils-common |
| LOW | CVE-2024-53589 | binutils: objdump: buffer Overflow in the BFD library's handling of tekhex format files | binutils-common |
| LOW | CVE-2024-57360 | binutils: nm: potential segmentation fault when displaying symbols without version info | binutils-common |
| LOW | CVE-2025-0840 | binutils: GNU Binutils objdump.c disassemble_bytes stack-based overflow | binutils-common |
| LOW | CVE-2017-13716 | binutils: Memory leak with the C++ symbol demangler routine in libiberty | binutils-x86-64-linux-gnu |
| LOW | CVE-2018-20673 | libiberty: Integer overflow in demangle_template() function | binutils-x86-64-linux-gnu |
| LOW | CVE-2018-20712 | libiberty: heap-based buffer over-read in d_expression_1 | binutils-x86-64-linux-gnu |
| LOW | CVE-2018-9996 | binutils: Stack-overflow in libiberty/cplus-dem.c causes crash | binutils-x86-64-linux-gnu |
| LOW | CVE-2021-32256 | binutils: stack-overflow issue in demangle_type in rust-demangle.c. | binutils-x86-64-linux-gnu |
| LOW | CVE-2023-1972 | binutils: Illegal memory access when accessing a zer0-lengthverdef table | binutils-x86-64-linux-gnu |
| LOW | CVE-2024-53589 | binutils: objdump: buffer Overflow in the BFD library's handling of tekhex format files | binutils-x86-64-linux-gnu |
| LOW | CVE-2024-57360 | binutils: nm: potential segmentation fault when displaying symbols without version info | binutils-x86-64-linux-gnu |
| LOW | CVE-2025-0840 | binutils: GNU Binutils objdump.c disassemble_bytes stack-based overflow | binutils-x86-64-linux-gnu |
| LOW | CVE-2022-0563 | util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline | bsdutils |
| LOW | CVE-2016-2781 | coreutils: Non-privileged session can escape to the parent session in chroot | coreutils |
| LOW | CVE-2017-18018 | coreutils: race condition vulnerability in chown and chgrp | coreutils |
| LOW | CVE-2022-27943 | binutils: libiberty/rust-demangle.c in GNU GCC 11.2 allows stack exhaustion in demangle_const | cpp-12 |
| LOW | CVE-2023-4039 | gcc: -fstack-protector fails to guard dynamic stack allocations on ARM64 | cpp-12 |
| MEDIUM | CVE-2024-11053 | curl: curl netrc password leak | curl |
| MEDIUM | CVE-2024-9681 | curl: HSTS subdomain overwrites parent cache entry | curl |
| LOW | CVE-2024-2379 | curl: QUIC certificate check bypass with wolfSSL | curl |
| LOW | CVE-2025-0167 | When asked to use a `.netrc` file for credentials **and** to follow HT ... | curl |
| LOW | CVE-2025-0725 | libcurl: Buffer Overflow in libcurl via zlib Integer Overflow | curl |
| LOW | CVE-2022-3219 | gnupg: denial of service issue (resource consumption) using compressed packets | dirmngr |
| LOW | CVE-2022-27943 | binutils: libiberty/rust-demangle.c in GNU GCC 11.2 allows stack exhaustion in demangle_const | g++-12 |
| LOW | CVE-2023-4039 | gcc: -fstack-protector fails to guard dynamic stack allocations on ARM64 | g++-12 |
| LOW | CVE-2022-27943 | binutils: libiberty/rust-demangle.c in GNU GCC 11.2 allows stack exhaustion in demangle_const | gcc-12 |
| LOW | CVE-2023-4039 | gcc: -fstack-protector fails to guard dynamic stack allocations on ARM64 | gcc-12 |
| LOW | CVE-2022-27943 | binutils: libiberty/rust-demangle.c in GNU GCC 11.2 allows stack exhaustion in demangle_const | gcc-12-base |
| LOW | CVE-2023-4039 | gcc: -fstack-protector fails to guard dynamic stack allocations on ARM64 | gcc-12-base |
| LOW | CVE-2018-1000021 | git: client prints server-sent ANSI escape codes to the terminal, allowing for unverified messages to potentially execute arbitrary commands | git |
| LOW | CVE-2022-24975 | git: The --mirror option for git leaks secret for deleted content, aka the "GitBleed" | git |
| LOW | CVE-2024-52005 | git: The sideband payload is passed unfiltered to the terminal in git | git |
| LOW | CVE-2018-1000021 | git: client prints server-sent ANSI escape codes to the terminal, allowing for unverified messages to potentially execute arbitrary commands | git-man |
| LOW | CVE-2022-24975 | git: The --mirror option for git leaks secret for deleted content, aka the "GitBleed" | git-man |
| LOW | CVE-2024-52005 | git: The sideband payload is passed unfiltered to the terminal in git | git-man |
| LOW | CVE-2022-3219 | gnupg: denial of service issue (resource consumption) using compressed packets | gnupg |
| LOW | CVE-2022-3219 | gnupg: denial of service issue (resource consumption) using compressed packets | gnupg-l10n |
| LOW | CVE-2022-3219 | gnupg: denial of service issue (resource consumption) using compressed packets | gnupg-utils |
| LOW | CVE-2022-3219 | gnupg: denial of service issue (resource consumption) using compressed packets | gpg |
| LOW | CVE-2022-3219 | gnupg: denial of service issue (resource consumption) using compressed packets | gpg-agent |
| LOW | CVE-2022-3219 | gnupg: denial of service issue (resource consumption) using compressed packets | gpg-wks-client |
| LOW | CVE-2022-3219 | gnupg: denial of service issue (resource consumption) using compressed packets | gpg-wks-server |
| LOW | CVE-2022-3219 | gnupg: denial of service issue (resource consumption) using compressed packets | gpgconf |
| LOW | CVE-2022-3219 | gnupg: denial of service issue (resource consumption) using compressed packets | gpgsm |
| LOW | CVE-2022-3219 | gnupg: denial of service issue (resource consumption) using compressed packets | gpgv |
| LOW | CVE-2005-0406 | A design flaw in image processing software that modifies JPEG images m ... | imagemagick |
| LOW | CVE-2008-3134 | GraphicsMagick/ImageMagick: multiple crash or DoS issues | imagemagick |
| LOW | CVE-2016-8678 | ImageMagick: Heap-buffer overflow in IsPixelMonochrome | imagemagick |
| LOW | CVE-2017-11754 | ImageMagick: Memory leak in WritePICONImage function | imagemagick |
| LOW | CVE-2017-11755 | ImageMagick: Memory leak in WritePICONImage function via mishandled AcquireSemaphoreInfo call | imagemagick |
| LOW | CVE-2017-7275 | ImageMagick: Memory allocation failure in AcquireMagickMemory (incomplete fix for  CVE-2016-8866) | imagemagick |
| LOW | CVE-2018-15607 | ImageMagick: CPU Exhaustion via crafted input file | imagemagick |
| LOW | CVE-2021-20311 | ImageMagick: Division by zero in sRGBTransformImage() in MagickCore/colorspace.c | imagemagick |
| LOW | CVE-2023-34152 | ImageMagick: RCE (shell command injection) vulnerability in OpenBlob with --enable-pipes configured | imagemagick |
| LOW | CVE-2005-0406 | A design flaw in image processing software that modifies JPEG images m ... | imagemagick-6-common |
| LOW | CVE-2008-3134 | GraphicsMagick/ImageMagick: multiple crash or DoS issues | imagemagick-6-common |
| LOW | CVE-2016-8678 | ImageMagick: Heap-buffer overflow in IsPixelMonochrome | imagemagick-6-common |
| LOW | CVE-2017-11754 | ImageMagick: Memory leak in WritePICONImage function | imagemagick-6-common |
| LOW | CVE-2017-11755 | ImageMagick: Memory leak in WritePICONImage function via mishandled AcquireSemaphoreInfo call | imagemagick-6-common |
| LOW | CVE-2017-7275 | ImageMagick: Memory allocation failure in AcquireMagickMemory (incomplete fix for  CVE-2016-8866) | imagemagick-6-common |
| LOW | CVE-2018-15607 | ImageMagick: CPU Exhaustion via crafted input file | imagemagick-6-common |
| LOW | CVE-2021-20311 | ImageMagick: Division by zero in sRGBTransformImage() in MagickCore/colorspace.c | imagemagick-6-common |
| LOW | CVE-2023-34152 | ImageMagick: RCE (shell command injection) vulnerability in OpenBlob with --enable-pipes configured | imagemagick-6-common |
| LOW | CVE-2005-0406 | A design flaw in image processing software that modifies JPEG images m ... | imagemagick-6.q16 |
| LOW | CVE-2008-3134 | GraphicsMagick/ImageMagick: multiple crash or DoS issues | imagemagick-6.q16 |
| LOW | CVE-2016-8678 | ImageMagick: Heap-buffer overflow in IsPixelMonochrome | imagemagick-6.q16 |
| LOW | CVE-2017-11754 | ImageMagick: Memory leak in WritePICONImage function | imagemagick-6.q16 |
| LOW | CVE-2017-11755 | ImageMagick: Memory leak in WritePICONImage function via mishandled AcquireSemaphoreInfo call | imagemagick-6.q16 |
| LOW | CVE-2017-7275 | ImageMagick: Memory allocation failure in AcquireMagickMemory (incomplete fix for  CVE-2016-8866) | imagemagick-6.q16 |
| LOW | CVE-2018-15607 | ImageMagick: CPU Exhaustion via crafted input file | imagemagick-6.q16 |
| LOW | CVE-2021-20311 | ImageMagick: Division by zero in sRGBTransformImage() in MagickCore/colorspace.c | imagemagick-6.q16 |
| LOW | CVE-2023-34152 | ImageMagick: RCE (shell command injection) vulnerability in OpenBlob with --enable-pipes configured | imagemagick-6.q16 |
| HIGH | CVE-2024-26462 | krb5: Memory leak at /krb5/src/kdc/ndr.c | krb5-multidev |
| MEDIUM | CVE-2025-24528 | krb5: overflow when calculating ulog block size | krb5-multidev |
| LOW | CVE-2018-5709 | krb5: integer overflow in dbentry->n_key_data in kadmin/dbutil/dump.c | krb5-multidev |
| LOW | CVE-2024-26458 | krb5: Memory leak at /krb5/src/lib/rpc/pmap_rmt.c | krb5-multidev |
| LOW | CVE-2024-26461 | krb5: Memory leak at /krb5/src/lib/gssapi/krb5/k5sealv3.c | krb5-multidev |
| CRITICAL | CVE-2023-6879 | aom: heap-buffer-overflow on frame size change | libaom3 |
| HIGH | CVE-2023-39616 | AOMedia v3.0.0 to v3.5.0 was discovered to contain an invalid read mem ... | libaom3 |
| LOW | CVE-2011-3374 | It was found that apt-key in apt, all versions, do not correctly valid ... | libapt-pkg6.0 |
| LOW | CVE-2022-27943 | binutils: libiberty/rust-demangle.c in GNU GCC 11.2 allows stack exhaustion in demangle_const | libasan8 |
| LOW | CVE-2023-4039 | gcc: -fstack-protector fails to guard dynamic stack allocations on ARM64 | libasan8 |
| LOW | CVE-2022-27943 | binutils: libiberty/rust-demangle.c in GNU GCC 11.2 allows stack exhaustion in demangle_const | libatomic1 |
| LOW | CVE-2023-4039 | gcc: -fstack-protector fails to guard dynamic stack allocations on ARM64 | libatomic1 |
| LOW | CVE-2017-13716 | binutils: Memory leak with the C++ symbol demangler routine in libiberty | libbinutils |
| LOW | CVE-2018-20673 | libiberty: Integer overflow in demangle_template() function | libbinutils |
| LOW | CVE-2018-20712 | libiberty: heap-based buffer over-read in d_expression_1 | libbinutils |
| LOW | CVE-2018-9996 | binutils: Stack-overflow in libiberty/cplus-dem.c causes crash | libbinutils |
| LOW | CVE-2021-32256 | binutils: stack-overflow issue in demangle_type in rust-demangle.c. | libbinutils |
| LOW | CVE-2023-1972 | binutils: Illegal memory access when accessing a zer0-lengthverdef table | libbinutils |
| LOW | CVE-2024-53589 | binutils: objdump: buffer Overflow in the BFD library's handling of tekhex format files | libbinutils |
| LOW | CVE-2024-57360 | binutils: nm: potential segmentation fault when displaying symbols without version info | libbinutils |
| LOW | CVE-2025-0840 | binutils: GNU Binutils objdump.c disassemble_bytes stack-based overflow | libbinutils |
| LOW | CVE-2022-0563 | util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline | libblkid-dev |
| LOW | CVE-2022-0563 | util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline | libblkid1 |
| HIGH | CVE-2023-44431 | bluez: AVRCP stack-based buffer overflow remote code execution vulnerability | libbluetooth-dev |
| HIGH | CVE-2023-51596 | bluez: phone book access profile heap-based buffer overflow remote code execution vulnerability | libbluetooth-dev |
| MEDIUM | CVE-2023-51580 | bluez: avrcp_parse_attribute_list out-of-bounds read information disclosure vulnerability | libbluetooth-dev |
| MEDIUM | CVE-2023-51589 | bluez: audio profile avrcp parse_media_element out-of-bounds read information disclosure vulnerability | libbluetooth-dev |
| MEDIUM | CVE-2023-51592 | bluez: audio profile avrcp parse_media_folder out-of-bounds read information disclosure vulnerability | libbluetooth-dev |
| LOW | CVE-2016-9797 | bluez: buffer over-read in l2cap_dump() | libbluetooth-dev |
| LOW | CVE-2016-9798 | bluez: use-after-free in conf_opt() | libbluetooth-dev |
| LOW | CVE-2016-9799 | bluez: buffer overflow in pklg_read_hci() | libbluetooth-dev |
| LOW | CVE-2016-9800 | bluez: buffer overflow in pin_code_reply_dump() | libbluetooth-dev |
| LOW | CVE-2016-9801 | bluez: buffer overflow in set_ext_ctrl() | libbluetooth-dev |
| LOW | CVE-2016-9802 | bluez: buffer over-read in l2cap_packet() | libbluetooth-dev |
| LOW | CVE-2016-9803 | bluez: out-of-bounds read in le_meta_ev_dump() | libbluetooth-dev |
| LOW | CVE-2016-9804 | bluez: buffer overflow in commands_dump() | libbluetooth-dev |
| LOW | CVE-2016-9917 | bluez: Heap-based buffer overflow vulnerability in read_n() | libbluetooth-dev |
| LOW | CVE-2016-9918 | bluez: Out of bounds stack read in packet_hexdump() | libbluetooth-dev |
| LOW | CVE-2023-51594 | bluez: OBEX library out-of-bounds read information disclosure vulnerability | libbluetooth-dev |
| HIGH | CVE-2023-44431 | bluez: AVRCP stack-based buffer overflow remote code execution vulnerability | libbluetooth3 |
| HIGH | CVE-2023-51596 | bluez: phone book access profile heap-based buffer overflow remote code execution vulnerability | libbluetooth3 |
| MEDIUM | CVE-2023-51580 | bluez: avrcp_parse_attribute_list out-of-bounds read information disclosure vulnerability | libbluetooth3 |
| MEDIUM | CVE-2023-51589 | bluez: audio profile avrcp parse_media_element out-of-bounds read information disclosure vulnerability | libbluetooth3 |
| MEDIUM | CVE-2023-51592 | bluez: audio profile avrcp parse_media_folder out-of-bounds read information disclosure vulnerability | libbluetooth3 |
| LOW | CVE-2016-9797 | bluez: buffer over-read in l2cap_dump() | libbluetooth3 |
| LOW | CVE-2016-9798 | bluez: use-after-free in conf_opt() | libbluetooth3 |
| LOW | CVE-2016-9799 | bluez: buffer overflow in pklg_read_hci() | libbluetooth3 |
| LOW | CVE-2016-9800 | bluez: buffer overflow in pin_code_reply_dump() | libbluetooth3 |
| LOW | CVE-2016-9801 | bluez: buffer overflow in set_ext_ctrl() | libbluetooth3 |
| LOW | CVE-2016-9802 | bluez: buffer over-read in l2cap_packet() | libbluetooth3 |
| LOW | CVE-2016-9803 | bluez: out-of-bounds read in le_meta_ev_dump() | libbluetooth3 |
| LOW | CVE-2016-9804 | bluez: buffer overflow in commands_dump() | libbluetooth3 |
| LOW | CVE-2016-9917 | bluez: Heap-based buffer overflow vulnerability in read_n() | libbluetooth3 |
| LOW | CVE-2016-9918 | bluez: Out of bounds stack read in packet_hexdump() | libbluetooth3 |
| LOW | CVE-2023-51594 | bluez: OBEX library out-of-bounds read information disclosure vulnerability | libbluetooth3 |
| MEDIUM | CVE-2025-0395 | glibc: buffer overflow in the GNU C Library's assert() | libc-bin |
| LOW | CVE-2010-4756 | glibc: glob implementation can cause excessive CPU and memory consumption due to crafted glob expressions | libc-bin |
| LOW | CVE-2018-20796 | glibc: uncontrolled recursion in function check_dst_limits_calc_pos_1 in posix/regexec.c | libc-bin |
| LOW | CVE-2019-1010022 | glibc: stack guard protection bypass | libc-bin |
| LOW | CVE-2019-1010023 | glibc: running ldd on malicious ELF leads to code execution because of wrong size computation | libc-bin |
| LOW | CVE-2019-1010024 | glibc: ASLR bypass using cache of thread stack and heap | libc-bin |
| LOW | CVE-2019-1010025 | glibc: information disclosure of heap addresses of pthread_created thread | libc-bin |
| LOW | CVE-2019-9192 | glibc: uncontrolled recursion in function check_dst_limits_calc_pos_1 in posix/regexec.c | libc-bin |
| MEDIUM | CVE-2025-0395 | glibc: buffer overflow in the GNU C Library's assert() | libc-dev-bin |
| LOW | CVE-2010-4756 | glibc: glob implementation can cause excessive CPU and memory consumption due to crafted glob expressions | libc-dev-bin |
| LOW | CVE-2018-20796 | glibc: uncontrolled recursion in function check_dst_limits_calc_pos_1 in posix/regexec.c | libc-dev-bin |
| LOW | CVE-2019-1010022 | glibc: stack guard protection bypass | libc-dev-bin |
| LOW | CVE-2019-1010023 | glibc: running ldd on malicious ELF leads to code execution because of wrong size computation | libc-dev-bin |
| LOW | CVE-2019-1010024 | glibc: ASLR bypass using cache of thread stack and heap | libc-dev-bin |
| LOW | CVE-2019-1010025 | glibc: information disclosure of heap addresses of pthread_created thread | libc-dev-bin |
| LOW | CVE-2019-9192 | glibc: uncontrolled recursion in function check_dst_limits_calc_pos_1 in posix/regexec.c | libc-dev-bin |
| MEDIUM | CVE-2025-0395 | glibc: buffer overflow in the GNU C Library's assert() | libc6 |
| LOW | CVE-2010-4756 | glibc: glob implementation can cause excessive CPU and memory consumption due to crafted glob expressions | libc6 |
| LOW | CVE-2018-20796 | glibc: uncontrolled recursion in function check_dst_limits_calc_pos_1 in posix/regexec.c | libc6 |
| LOW | CVE-2019-1010022 | glibc: stack guard protection bypass | libc6 |
| LOW | CVE-2019-1010023 | glibc: running ldd on malicious ELF leads to code execution because of wrong size computation | libc6 |
| LOW | CVE-2019-1010024 | glibc: ASLR bypass using cache of thread stack and heap | libc6 |
| LOW | CVE-2019-1010025 | glibc: information disclosure of heap addresses of pthread_created thread | libc6 |
| LOW | CVE-2019-9192 | glibc: uncontrolled recursion in function check_dst_limits_calc_pos_1 in posix/regexec.c | libc6 |
| MEDIUM | CVE-2025-0395 | glibc: buffer overflow in the GNU C Library's assert() | libc6-dev |
| LOW | CVE-2010-4756 | glibc: glob implementation can cause excessive CPU and memory consumption due to crafted glob expressions | libc6-dev |
| LOW | CVE-2018-20796 | glibc: uncontrolled recursion in function check_dst_limits_calc_pos_1 in posix/regexec.c | libc6-dev |
| LOW | CVE-2019-1010022 | glibc: stack guard protection bypass | libc6-dev |
| LOW | CVE-2019-1010023 | glibc: running ldd on malicious ELF leads to code execution because of wrong size computation | libc6-dev |
| LOW | CVE-2019-1010024 | glibc: ASLR bypass using cache of thread stack and heap | libc6-dev |
| LOW | CVE-2019-1010025 | glibc: information disclosure of heap addresses of pthread_created thread | libc6-dev |
| LOW | CVE-2019-9192 | glibc: uncontrolled recursion in function check_dst_limits_calc_pos_1 in posix/regexec.c | libc6-dev |
| LOW | CVE-2017-7475 | cairo: NULL pointer dereference with a crafted font file | libcairo-gobject2 |
| LOW | CVE-2018-18064 | cairo: Stack-based buffer overflow via parsing of crafted WebKitGTK+ document | libcairo-gobject2 |
| LOW | CVE-2019-6461 | cairo: assertion problem in _cairo_arc_in_direction in cairo-arc.c | libcairo-gobject2 |
| LOW | CVE-2019-6462 | cairo: infinite loop in the function _arc_error_normalized in the file cairo-arc.c | libcairo-gobject2 |
| LOW | CVE-2017-7475 | cairo: NULL pointer dereference with a crafted font file | libcairo-script-interpreter2 |
| LOW | CVE-2018-18064 | cairo: Stack-based buffer overflow via parsing of crafted WebKitGTK+ document | libcairo-script-interpreter2 |
| LOW | CVE-2019-6461 | cairo: assertion problem in _cairo_arc_in_direction in cairo-arc.c | libcairo-script-interpreter2 |
| LOW | CVE-2019-6462 | cairo: infinite loop in the function _arc_error_normalized in the file cairo-arc.c | libcairo-script-interpreter2 |
| LOW | CVE-2017-7475 | cairo: NULL pointer dereference with a crafted font file | libcairo2 |
| LOW | CVE-2018-18064 | cairo: Stack-based buffer overflow via parsing of crafted WebKitGTK+ document | libcairo2 |
| LOW | CVE-2019-6461 | cairo: assertion problem in _cairo_arc_in_direction in cairo-arc.c | libcairo2 |
| LOW | CVE-2019-6462 | cairo: infinite loop in the function _arc_error_normalized in the file cairo-arc.c | libcairo2 |
| LOW | CVE-2017-7475 | cairo: NULL pointer dereference with a crafted font file | libcairo2-dev |
| LOW | CVE-2018-18064 | cairo: Stack-based buffer overflow via parsing of crafted WebKitGTK+ document | libcairo2-dev |
| LOW | CVE-2019-6461 | cairo: assertion problem in _cairo_arc_in_direction in cairo-arc.c | libcairo2-dev |
| LOW | CVE-2019-6462 | cairo: infinite loop in the function _arc_error_normalized in the file cairo-arc.c | libcairo2-dev |
| LOW | CVE-2022-27943 | binutils: libiberty/rust-demangle.c in GNU GCC 11.2 allows stack exhaustion in demangle_const | libcc1-0 |
| LOW | CVE-2023-4039 | gcc: -fstack-protector fails to guard dynamic stack allocations on ARM64 | libcc1-0 |
| LOW | CVE-2017-13716 | binutils: Memory leak with the C++ symbol demangler routine in libiberty | libctf-nobfd0 |
| LOW | CVE-2018-20673 | libiberty: Integer overflow in demangle_template() function | libctf-nobfd0 |
| LOW | CVE-2018-20712 | libiberty: heap-based buffer over-read in d_expression_1 | libctf-nobfd0 |
| LOW | CVE-2018-9996 | binutils: Stack-overflow in libiberty/cplus-dem.c causes crash | libctf-nobfd0 |
| LOW | CVE-2021-32256 | binutils: stack-overflow issue in demangle_type in rust-demangle.c. | libctf-nobfd0 |
| LOW | CVE-2023-1972 | binutils: Illegal memory access when accessing a zer0-lengthverdef table | libctf-nobfd0 |
| LOW | CVE-2024-53589 | binutils: objdump: buffer Overflow in the BFD library's handling of tekhex format files | libctf-nobfd0 |
| LOW | CVE-2024-57360 | binutils: nm: potential segmentation fault when displaying symbols without version info | libctf-nobfd0 |
| LOW | CVE-2025-0840 | binutils: GNU Binutils objdump.c disassemble_bytes stack-based overflow | libctf-nobfd0 |
| LOW | CVE-2017-13716 | binutils: Memory leak with the C++ symbol demangler routine in libiberty | libctf0 |
| LOW | CVE-2018-20673 | libiberty: Integer overflow in demangle_template() function | libctf0 |
| LOW | CVE-2018-20712 | libiberty: heap-based buffer over-read in d_expression_1 | libctf0 |
| LOW | CVE-2018-9996 | binutils: Stack-overflow in libiberty/cplus-dem.c causes crash | libctf0 |
| LOW | CVE-2021-32256 | binutils: stack-overflow issue in demangle_type in rust-demangle.c. | libctf0 |
| LOW | CVE-2023-1972 | binutils: Illegal memory access when accessing a zer0-lengthverdef table | libctf0 |
| LOW | CVE-2024-53589 | binutils: objdump: buffer Overflow in the BFD library's handling of tekhex format files | libctf0 |
| LOW | CVE-2024-57360 | binutils: nm: potential segmentation fault when displaying symbols without version info | libctf0 |
| LOW | CVE-2025-0840 | binutils: GNU Binutils objdump.c disassemble_bytes stack-based overflow | libctf0 |
| MEDIUM | CVE-2024-11053 | curl: curl netrc password leak | libcurl3-gnutls |
| MEDIUM | CVE-2024-9681 | curl: HSTS subdomain overwrites parent cache entry | libcurl3-gnutls |
| LOW | CVE-2024-2379 | curl: QUIC certificate check bypass with wolfSSL | libcurl3-gnutls |
| LOW | CVE-2025-0167 | When asked to use a `.netrc` file for credentials **and** to follow HT ... | libcurl3-gnutls |
| LOW | CVE-2025-0725 | libcurl: Buffer Overflow in libcurl via zlib Integer Overflow | libcurl3-gnutls |
| MEDIUM | CVE-2024-11053 | curl: curl netrc password leak | libcurl4 |
| MEDIUM | CVE-2024-9681 | curl: HSTS subdomain overwrites parent cache entry | libcurl4 |
| LOW | CVE-2024-2379 | curl: QUIC certificate check bypass with wolfSSL | libcurl4 |
| LOW | CVE-2025-0167 | When asked to use a `.netrc` file for credentials **and** to follow HT ... | libcurl4 |
| LOW | CVE-2025-0725 | libcurl: Buffer Overflow in libcurl via zlib Integer Overflow | libcurl4 |
| MEDIUM | CVE-2024-11053 | curl: curl netrc password leak | libcurl4-openssl-dev |
| MEDIUM | CVE-2024-9681 | curl: HSTS subdomain overwrites parent cache entry | libcurl4-openssl-dev |
| LOW | CVE-2024-2379 | curl: QUIC certificate check bypass with wolfSSL | libcurl4-openssl-dev |
| LOW | CVE-2025-0167 | When asked to use a `.netrc` file for credentials **and** to follow HT ... | libcurl4-openssl-dev |
| LOW | CVE-2025-0725 | libcurl: Buffer Overflow in libcurl via zlib Integer Overflow | libcurl4-openssl-dev |
| MEDIUM | CVE-2023-32570 | VideoLAN dav1d before 1.2.0 has a thread_task.c race condition that ca ... | libdav1d6 |
| MEDIUM | CVE-2023-51792 | Buffer Overflow vulnerability in libde265 v1.0.12 allows a local attac ... | libde265-0 |
| MEDIUM | CVE-2024-38949 | Heap Buffer Overflow vulnerability in Libde265 v1.0.15 allows attacker ... | libde265-0 |
| MEDIUM | CVE-2024-38950 | Heap Buffer Overflow vulnerability in Libde265 v1.0.15 allows attacker ... | libde265-0 |
| MEDIUM | CVE-2021-46310 | An issue was discovered IW44Image.cpp in djvulibre 3.5.28 in allows at ... | libdjvulibre-dev |
| MEDIUM | CVE-2021-46312 | An issue was discovered IW44EncodeCodec.cpp in djvulibre 3.5.28 in all ... | libdjvulibre-dev |
| MEDIUM | CVE-2021-46310 | An issue was discovered IW44Image.cpp in djvulibre 3.5.28 in allows at ... | libdjvulibre-text |
| MEDIUM | CVE-2021-46312 | An issue was discovered IW44EncodeCodec.cpp in djvulibre 3.5.28 in all ... | libdjvulibre-text |
| MEDIUM | CVE-2021-46310 | An issue was discovered IW44Image.cpp in djvulibre 3.5.28 in allows at ... | libdjvulibre21 |
| MEDIUM | CVE-2021-46312 | An issue was discovered IW44EncodeCodec.cpp in djvulibre 3.5.28 in all ... | libdjvulibre21 |
| LOW | CVE-2024-25260 | elfutils: global-buffer-overflow exists in the function ebl_machine_flag_name in eblmachineflagname.c | libelf1 |
| HIGH | CVE-2023-52425 | expat: parsing large tokens can trigger a denial of service | libexpat1 |
| MEDIUM | CVE-2024-50602 | libexpat: expat: DoS via XML_ResumeParser | libexpat1 |
| LOW | CVE-2023-52426 | expat: recursive XML entity expansion vulnerability | libexpat1 |
| LOW | CVE-2024-28757 | expat: XML Entity Expansion | libexpat1 |
| HIGH | CVE-2023-52425 | expat: parsing large tokens can trigger a denial of service | libexpat1-dev |
| MEDIUM | CVE-2024-50602 | libexpat: expat: DoS via XML_ResumeParser | libexpat1-dev |
| LOW | CVE-2023-52426 | expat: recursive XML entity expansion vulnerability | libexpat1-dev |
| LOW | CVE-2024-28757 | expat: XML Entity Expansion | libexpat1-dev |
| LOW | CVE-2022-27943 | binutils: libiberty/rust-demangle.c in GNU GCC 11.2 allows stack exhaustion in demangle_const | libgcc-12-dev |
| LOW | CVE-2023-4039 | gcc: -fstack-protector fails to guard dynamic stack allocations on ARM64 | libgcc-12-dev |
| LOW | CVE-2022-27943 | binutils: libiberty/rust-demangle.c in GNU GCC 11.2 allows stack exhaustion in demangle_const | libgcc-s1 |
| LOW | CVE-2023-4039 | gcc: -fstack-protector fails to guard dynamic stack allocations on ARM64 | libgcc-s1 |
| MEDIUM | CVE-2024-2236 | libgcrypt: vulnerable to Marvin Attack | libgcrypt20 |
| LOW | CVE-2018-6829 | libgcrypt: ElGamal implementation doesn't have semantic security due to incorrectly encoded plaintexts possibly allowing to obtain sensitive information | libgcrypt20 |
| LOW | CVE-2012-0039 | glib2: hash table collisions CPU usage DoS | libglib2.0-0 |
| LOW | CVE-2012-0039 | glib2: hash table collisions CPU usage DoS | libglib2.0-bin |
| LOW | CVE-2012-0039 | glib2: hash table collisions CPU usage DoS | libglib2.0-data |
| LOW | CVE-2012-0039 | glib2: hash table collisions CPU usage DoS | libglib2.0-dev |
| LOW | CVE-2012-0039 | glib2: hash table collisions CPU usage DoS | libglib2.0-dev-bin |
| LOW | CVE-2011-3389 | HTTPS: block-wise chosen-plaintext attack against SSL/TLS (BEAST) | libgnutls30 |
| LOW | CVE-2022-27943 | binutils: libiberty/rust-demangle.c in GNU GCC 11.2 allows stack exhaustion in demangle_const | libgomp1 |
| LOW | CVE-2023-4039 | gcc: -fstack-protector fails to guard dynamic stack allocations on ARM64 | libgomp1 |
| LOW | CVE-2017-13716 | binutils: Memory leak with the C++ symbol demangler routine in libiberty | libgprofng0 |
| LOW | CVE-2018-20673 | libiberty: Integer overflow in demangle_template() function | libgprofng0 |
| LOW | CVE-2018-20712 | libiberty: heap-based buffer over-read in d_expression_1 | libgprofng0 |
| LOW | CVE-2018-9996 | binutils: Stack-overflow in libiberty/cplus-dem.c causes crash | libgprofng0 |
| LOW | CVE-2021-32256 | binutils: stack-overflow issue in demangle_type in rust-demangle.c. | libgprofng0 |
| LOW | CVE-2023-1972 | binutils: Illegal memory access when accessing a zer0-lengthverdef table | libgprofng0 |
| LOW | CVE-2024-53589 | binutils: objdump: buffer Overflow in the BFD library's handling of tekhex format files | libgprofng0 |
| LOW | CVE-2024-57360 | binutils: nm: potential segmentation fault when displaying symbols without version info | libgprofng0 |
| LOW | CVE-2025-0840 | binutils: GNU Binutils objdump.c disassemble_bytes stack-based overflow | libgprofng0 |
| HIGH | CVE-2024-26462 | krb5: Memory leak at /krb5/src/kdc/ndr.c | libgssapi-krb5-2 |
| MEDIUM | CVE-2025-24528 | krb5: overflow when calculating ulog block size | libgssapi-krb5-2 |
| LOW | CVE-2018-5709 | krb5: integer overflow in dbentry->n_key_data in kadmin/dbutil/dump.c | libgssapi-krb5-2 |
| LOW | CVE-2024-26458 | krb5: Memory leak at /krb5/src/lib/rpc/pmap_rmt.c | libgssapi-krb5-2 |
| LOW | CVE-2024-26461 | krb5: Memory leak at /krb5/src/lib/gssapi/krb5/k5sealv3.c | libgssapi-krb5-2 |
| HIGH | CVE-2024-26462 | krb5: Memory leak at /krb5/src/kdc/ndr.c | libgssrpc4 |
| MEDIUM | CVE-2025-24528 | krb5: overflow when calculating ulog block size | libgssrpc4 |
| LOW | CVE-2018-5709 | krb5: integer overflow in dbentry->n_key_data in kadmin/dbutil/dump.c | libgssrpc4 |
| LOW | CVE-2024-26458 | krb5: Memory leak at /krb5/src/lib/rpc/pmap_rmt.c | libgssrpc4 |
| LOW | CVE-2024-26461 | krb5: Memory leak at /krb5/src/lib/gssapi/krb5/k5sealv3.c | libgssrpc4 |
| HIGH | CVE-2023-25193 | harfbuzz: allows attackers to trigger O(n^2) growth via consecutive marks | libharfbuzz0b |
| LOW | CVE-2023-49463 | libheif v1.17.5 was discovered to contain a segmentation violation via ... | libheif1 |
| LOW | CVE-2024-25269 | libheif <= 1.17.6 contains a memory leak in the function JpegEncoder:: ... | libheif1 |
| LOW | CVE-2022-27943 | binutils: libiberty/rust-demangle.c in GNU GCC 11.2 allows stack exhaustion in demangle_const | libitm1 |
| LOW | CVE-2023-4039 | gcc: -fstack-protector fails to guard dynamic stack allocations on ARM64 | libitm1 |
| LOW | CVE-2020-36325 | jansson: out-of-bounds read in json_loads() due to a parsing error | libjansson4 |
| LOW | CVE-2017-9937 | libtiff: memory malloc failure in tif_jbig.c could cause DOS. | libjbig-dev |
| LOW | CVE-2017-9937 | libtiff: memory malloc failure in tif_jbig.c could cause DOS. | libjbig0 |
| HIGH | CVE-2024-26462 | krb5: Memory leak at /krb5/src/kdc/ndr.c | libk5crypto3 |
| MEDIUM | CVE-2025-24528 | krb5: overflow when calculating ulog block size | libk5crypto3 |
| LOW | CVE-2018-5709 | krb5: integer overflow in dbentry->n_key_data in kadmin/dbutil/dump.c | libk5crypto3 |
| LOW | CVE-2024-26458 | krb5: Memory leak at /krb5/src/lib/rpc/pmap_rmt.c | libk5crypto3 |
| LOW | CVE-2024-26461 | krb5: Memory leak at /krb5/src/lib/gssapi/krb5/k5sealv3.c | libk5crypto3 |
| HIGH | CVE-2024-26462 | krb5: Memory leak at /krb5/src/kdc/ndr.c | libkadm5clnt-mit12 |
| MEDIUM | CVE-2025-24528 | krb5: overflow when calculating ulog block size | libkadm5clnt-mit12 |
| LOW | CVE-2018-5709 | krb5: integer overflow in dbentry->n_key_data in kadmin/dbutil/dump.c | libkadm5clnt-mit12 |
| LOW | CVE-2024-26458 | krb5: Memory leak at /krb5/src/lib/rpc/pmap_rmt.c | libkadm5clnt-mit12 |
| LOW | CVE-2024-26461 | krb5: Memory leak at /krb5/src/lib/gssapi/krb5/k5sealv3.c | libkadm5clnt-mit12 |
| HIGH | CVE-2024-26462 | krb5: Memory leak at /krb5/src/kdc/ndr.c | libkadm5srv-mit12 |
| MEDIUM | CVE-2025-24528 | krb5: overflow when calculating ulog block size | libkadm5srv-mit12 |
| LOW | CVE-2018-5709 | krb5: integer overflow in dbentry->n_key_data in kadmin/dbutil/dump.c | libkadm5srv-mit12 |
| LOW | CVE-2024-26458 | krb5: Memory leak at /krb5/src/lib/rpc/pmap_rmt.c | libkadm5srv-mit12 |
| LOW | CVE-2024-26461 | krb5: Memory leak at /krb5/src/lib/gssapi/krb5/k5sealv3.c | libkadm5srv-mit12 |
| HIGH | CVE-2024-26462 | krb5: Memory leak at /krb5/src/kdc/ndr.c | libkdb5-10 |
| MEDIUM | CVE-2025-24528 | krb5: overflow when calculating ulog block size | libkdb5-10 |
| LOW | CVE-2018-5709 | krb5: integer overflow in dbentry->n_key_data in kadmin/dbutil/dump.c | libkdb5-10 |
| LOW | CVE-2024-26458 | krb5: Memory leak at /krb5/src/lib/rpc/pmap_rmt.c | libkdb5-10 |
| LOW | CVE-2024-26461 | krb5: Memory leak at /krb5/src/lib/gssapi/krb5/k5sealv3.c | libkdb5-10 |
| HIGH | CVE-2024-26462 | krb5: Memory leak at /krb5/src/kdc/ndr.c | libkrb5-3 |
| MEDIUM | CVE-2025-24528 | krb5: overflow when calculating ulog block size | libkrb5-3 |
| LOW | CVE-2018-5709 | krb5: integer overflow in dbentry->n_key_data in kadmin/dbutil/dump.c | libkrb5-3 |
| LOW | CVE-2024-26458 | krb5: Memory leak at /krb5/src/lib/rpc/pmap_rmt.c | libkrb5-3 |
| LOW | CVE-2024-26461 | krb5: Memory leak at /krb5/src/lib/gssapi/krb5/k5sealv3.c | libkrb5-3 |
| HIGH | CVE-2024-26462 | krb5: Memory leak at /krb5/src/kdc/ndr.c | libkrb5-dev |
| MEDIUM | CVE-2025-24528 | krb5: overflow when calculating ulog block size | libkrb5-dev |
| LOW | CVE-2018-5709 | krb5: integer overflow in dbentry->n_key_data in kadmin/dbutil/dump.c | libkrb5-dev |
| LOW | CVE-2024-26458 | krb5: Memory leak at /krb5/src/lib/rpc/pmap_rmt.c | libkrb5-dev |
| LOW | CVE-2024-26461 | krb5: Memory leak at /krb5/src/lib/gssapi/krb5/k5sealv3.c | libkrb5-dev |
| HIGH | CVE-2024-26462 | krb5: Memory leak at /krb5/src/kdc/ndr.c | libkrb5support0 |
| MEDIUM | CVE-2025-24528 | krb5: overflow when calculating ulog block size | libkrb5support0 |
| LOW | CVE-2018-5709 | krb5: integer overflow in dbentry->n_key_data in kadmin/dbutil/dump.c | libkrb5support0 |
| LOW | CVE-2024-26458 | krb5: Memory leak at /krb5/src/lib/rpc/pmap_rmt.c | libkrb5support0 |
| LOW | CVE-2024-26461 | krb5: Memory leak at /krb5/src/lib/gssapi/krb5/k5sealv3.c | libkrb5support0 |
| HIGH | CVE-2023-2953 | openldap: null pointer dereference in  ber_memalloc_x  function | libldap-2.5-0 |
| LOW | CVE-2015-3276 | openldap: incorrect multi-keyword mode cipherstring parsing | libldap-2.5-0 |
| LOW | CVE-2017-14159 | openldap: Privilege escalation via PID file manipulation | libldap-2.5-0 |
| LOW | CVE-2017-17740 | openldap: contrib/slapd-modules/nops/nops.c attempts to free stack buffer allowing remote attackers to cause a denial of service | libldap-2.5-0 |
| LOW | CVE-2020-15719 | openldap: Certificate validation incorrectly matches name against CN-ID | libldap-2.5-0 |
| LOW | CVE-2022-27943 | binutils: libiberty/rust-demangle.c in GNU GCC 11.2 allows stack exhaustion in demangle_const | liblsan0 |
| LOW | CVE-2023-4039 | gcc: -fstack-protector fails to guard dynamic stack allocations on ARM64 | liblsan0 |
| LOW | CVE-2005-0406 | A design flaw in image processing software that modifies JPEG images m ... | libmagickcore-6-arch-config |
| LOW | CVE-2008-3134 | GraphicsMagick/ImageMagick: multiple crash or DoS issues | libmagickcore-6-arch-config |
| LOW | CVE-2016-8678 | ImageMagick: Heap-buffer overflow in IsPixelMonochrome | libmagickcore-6-arch-config |
| LOW | CVE-2017-11754 | ImageMagick: Memory leak in WritePICONImage function | libmagickcore-6-arch-config |
| LOW | CVE-2017-11755 | ImageMagick: Memory leak in WritePICONImage function via mishandled AcquireSemaphoreInfo call | libmagickcore-6-arch-config |
| LOW | CVE-2017-7275 | ImageMagick: Memory allocation failure in AcquireMagickMemory (incomplete fix for  CVE-2016-8866) | libmagickcore-6-arch-config |
| LOW | CVE-2018-15607 | ImageMagick: CPU Exhaustion via crafted input file | libmagickcore-6-arch-config |
| LOW | CVE-2021-20311 | ImageMagick: Division by zero in sRGBTransformImage() in MagickCore/colorspace.c | libmagickcore-6-arch-config |
| LOW | CVE-2023-34152 | ImageMagick: RCE (shell command injection) vulnerability in OpenBlob with --enable-pipes configured | libmagickcore-6-arch-config |
| LOW | CVE-2005-0406 | A design flaw in image processing software that modifies JPEG images m ... | libmagickcore-6-headers |
| LOW | CVE-2008-3134 | GraphicsMagick/ImageMagick: multiple crash or DoS issues | libmagickcore-6-headers |
| LOW | CVE-2016-8678 | ImageMagick: Heap-buffer overflow in IsPixelMonochrome | libmagickcore-6-headers |
| LOW | CVE-2017-11754 | ImageMagick: Memory leak in WritePICONImage function | libmagickcore-6-headers |
| LOW | CVE-2017-11755 | ImageMagick: Memory leak in WritePICONImage function via mishandled AcquireSemaphoreInfo call | libmagickcore-6-headers |
| LOW | CVE-2017-7275 | ImageMagick: Memory allocation failure in AcquireMagickMemory (incomplete fix for  CVE-2016-8866) | libmagickcore-6-headers |
| LOW | CVE-2018-15607 | ImageMagick: CPU Exhaustion via crafted input file | libmagickcore-6-headers |
| LOW | CVE-2021-20311 | ImageMagick: Division by zero in sRGBTransformImage() in MagickCore/colorspace.c | libmagickcore-6-headers |
| LOW | CVE-2023-34152 | ImageMagick: RCE (shell command injection) vulnerability in OpenBlob with --enable-pipes configured | libmagickcore-6-headers |
| LOW | CVE-2005-0406 | A design flaw in image processing software that modifies JPEG images m ... | libmagickcore-6.q16-6 |
| LOW | CVE-2008-3134 | GraphicsMagick/ImageMagick: multiple crash or DoS issues | libmagickcore-6.q16-6 |
| LOW | CVE-2016-8678 | ImageMagick: Heap-buffer overflow in IsPixelMonochrome | libmagickcore-6.q16-6 |
| LOW | CVE-2017-11754 | ImageMagick: Memory leak in WritePICONImage function | libmagickcore-6.q16-6 |
| LOW | CVE-2017-11755 | ImageMagick: Memory leak in WritePICONImage function via mishandled AcquireSemaphoreInfo call | libmagickcore-6.q16-6 |
| LOW | CVE-2017-7275 | ImageMagick: Memory allocation failure in AcquireMagickMemory (incomplete fix for  CVE-2016-8866) | libmagickcore-6.q16-6 |
| LOW | CVE-2018-15607 | ImageMagick: CPU Exhaustion via crafted input file | libmagickcore-6.q16-6 |
| LOW | CVE-2021-20311 | ImageMagick: Division by zero in sRGBTransformImage() in MagickCore/colorspace.c | libmagickcore-6.q16-6 |
| LOW | CVE-2023-34152 | ImageMagick: RCE (shell command injection) vulnerability in OpenBlob with --enable-pipes configured | libmagickcore-6.q16-6 |
| LOW | CVE-2005-0406 | A design flaw in image processing software that modifies JPEG images m ... | libmagickcore-6.q16-6-extra |
| LOW | CVE-2008-3134 | GraphicsMagick/ImageMagick: multiple crash or DoS issues | libmagickcore-6.q16-6-extra |
| LOW | CVE-2016-8678 | ImageMagick: Heap-buffer overflow in IsPixelMonochrome | libmagickcore-6.q16-6-extra |
| LOW | CVE-2017-11754 | ImageMagick: Memory leak in WritePICONImage function | libmagickcore-6.q16-6-extra |
| LOW | CVE-2017-11755 | ImageMagick: Memory leak in WritePICONImage function via mishandled AcquireSemaphoreInfo call | libmagickcore-6.q16-6-extra |
| LOW | CVE-2017-7275 | ImageMagick: Memory allocation failure in AcquireMagickMemory (incomplete fix for  CVE-2016-8866) | libmagickcore-6.q16-6-extra |
| LOW | CVE-2018-15607 | ImageMagick: CPU Exhaustion via crafted input file | libmagickcore-6.q16-6-extra |
| LOW | CVE-2021-20311 | ImageMagick: Division by zero in sRGBTransformImage() in MagickCore/colorspace.c | libmagickcore-6.q16-6-extra |
| LOW | CVE-2023-34152 | ImageMagick: RCE (shell command injection) vulnerability in OpenBlob with --enable-pipes configured | libmagickcore-6.q16-6-extra |
| LOW | CVE-2005-0406 | A design flaw in image processing software that modifies JPEG images m ... | libmagickcore-6.q16-dev |
| LOW | CVE-2008-3134 | GraphicsMagick/ImageMagick: multiple crash or DoS issues | libmagickcore-6.q16-dev |
| LOW | CVE-2016-8678 | ImageMagick: Heap-buffer overflow in IsPixelMonochrome | libmagickcore-6.q16-dev |
| LOW | CVE-2017-11754 | ImageMagick: Memory leak in WritePICONImage function | libmagickcore-6.q16-dev |
| LOW | CVE-2017-11755 | ImageMagick: Memory leak in WritePICONImage function via mishandled AcquireSemaphoreInfo call | libmagickcore-6.q16-dev |
| LOW | CVE-2017-7275 | ImageMagick: Memory allocation failure in AcquireMagickMemory (incomplete fix for  CVE-2016-8866) | libmagickcore-6.q16-dev |
| LOW | CVE-2018-15607 | ImageMagick: CPU Exhaustion via crafted input file | libmagickcore-6.q16-dev |
| LOW | CVE-2021-20311 | ImageMagick: Division by zero in sRGBTransformImage() in MagickCore/colorspace.c | libmagickcore-6.q16-dev |
| LOW | CVE-2023-34152 | ImageMagick: RCE (shell command injection) vulnerability in OpenBlob with --enable-pipes configured | libmagickcore-6.q16-dev |
| LOW | CVE-2005-0406 | A design flaw in image processing software that modifies JPEG images m ... | libmagickcore-dev |
| LOW | CVE-2008-3134 | GraphicsMagick/ImageMagick: multiple crash or DoS issues | libmagickcore-dev |
| LOW | CVE-2016-8678 | ImageMagick: Heap-buffer overflow in IsPixelMonochrome | libmagickcore-dev |
| LOW | CVE-2017-11754 | ImageMagick: Memory leak in WritePICONImage function | libmagickcore-dev |
| LOW | CVE-2017-11755 | ImageMagick: Memory leak in WritePICONImage function via mishandled AcquireSemaphoreInfo call | libmagickcore-dev |
| LOW | CVE-2017-7275 | ImageMagick: Memory allocation failure in AcquireMagickMemory (incomplete fix for  CVE-2016-8866) | libmagickcore-dev |
| LOW | CVE-2018-15607 | ImageMagick: CPU Exhaustion via crafted input file | libmagickcore-dev |
| LOW | CVE-2021-20311 | ImageMagick: Division by zero in sRGBTransformImage() in MagickCore/colorspace.c | libmagickcore-dev |
| LOW | CVE-2023-34152 | ImageMagick: RCE (shell command injection) vulnerability in OpenBlob with --enable-pipes configured | libmagickcore-dev |
| LOW | CVE-2005-0406 | A design flaw in image processing software that modifies JPEG images m ... | libmagickwand-6-headers |
| LOW | CVE-2008-3134 | GraphicsMagick/ImageMagick: multiple crash or DoS issues | libmagickwand-6-headers |
| LOW | CVE-2016-8678 | ImageMagick: Heap-buffer overflow in IsPixelMonochrome | libmagickwand-6-headers |
| LOW | CVE-2017-11754 | ImageMagick: Memory leak in WritePICONImage function | libmagickwand-6-headers |
| LOW | CVE-2017-11755 | ImageMagick: Memory leak in WritePICONImage function via mishandled AcquireSemaphoreInfo call | libmagickwand-6-headers |
| LOW | CVE-2017-7275 | ImageMagick: Memory allocation failure in AcquireMagickMemory (incomplete fix for  CVE-2016-8866) | libmagickwand-6-headers |
| LOW | CVE-2018-15607 | ImageMagick: CPU Exhaustion via crafted input file | libmagickwand-6-headers |
| LOW | CVE-2021-20311 | ImageMagick: Division by zero in sRGBTransformImage() in MagickCore/colorspace.c | libmagickwand-6-headers |
| LOW | CVE-2023-34152 | ImageMagick: RCE (shell command injection) vulnerability in OpenBlob with --enable-pipes configured | libmagickwand-6-headers |
| LOW | CVE-2005-0406 | A design flaw in image processing software that modifies JPEG images m ... | libmagickwand-6.q16-6 |
| LOW | CVE-2008-3134 | GraphicsMagick/ImageMagick: multiple crash or DoS issues | libmagickwand-6.q16-6 |
| LOW | CVE-2016-8678 | ImageMagick: Heap-buffer overflow in IsPixelMonochrome | libmagickwand-6.q16-6 |
| LOW | CVE-2017-11754 | ImageMagick: Memory leak in WritePICONImage function | libmagickwand-6.q16-6 |
| LOW | CVE-2017-11755 | ImageMagick: Memory leak in WritePICONImage function via mishandled AcquireSemaphoreInfo call | libmagickwand-6.q16-6 |
| LOW | CVE-2017-7275 | ImageMagick: Memory allocation failure in AcquireMagickMemory (incomplete fix for  CVE-2016-8866) | libmagickwand-6.q16-6 |
| LOW | CVE-2018-15607 | ImageMagick: CPU Exhaustion via crafted input file | libmagickwand-6.q16-6 |
| LOW | CVE-2021-20311 | ImageMagick: Division by zero in sRGBTransformImage() in MagickCore/colorspace.c | libmagickwand-6.q16-6 |
| LOW | CVE-2023-34152 | ImageMagick: RCE (shell command injection) vulnerability in OpenBlob with --enable-pipes configured | libmagickwand-6.q16-6 |
| LOW | CVE-2005-0406 | A design flaw in image processing software that modifies JPEG images m ... | libmagickwand-6.q16-dev |
| LOW | CVE-2008-3134 | GraphicsMagick/ImageMagick: multiple crash or DoS issues | libmagickwand-6.q16-dev |
| LOW | CVE-2016-8678 | ImageMagick: Heap-buffer overflow in IsPixelMonochrome | libmagickwand-6.q16-dev |
| LOW | CVE-2017-11754 | ImageMagick: Memory leak in WritePICONImage function | libmagickwand-6.q16-dev |
| LOW | CVE-2017-11755 | ImageMagick: Memory leak in WritePICONImage function via mishandled AcquireSemaphoreInfo call | libmagickwand-6.q16-dev |
| LOW | CVE-2017-7275 | ImageMagick: Memory allocation failure in AcquireMagickMemory (incomplete fix for  CVE-2016-8866) | libmagickwand-6.q16-dev |
| LOW | CVE-2018-15607 | ImageMagick: CPU Exhaustion via crafted input file | libmagickwand-6.q16-dev |
| LOW | CVE-2021-20311 | ImageMagick: Division by zero in sRGBTransformImage() in MagickCore/colorspace.c | libmagickwand-6.q16-dev |
| LOW | CVE-2023-34152 | ImageMagick: RCE (shell command injection) vulnerability in OpenBlob with --enable-pipes configured | libmagickwand-6.q16-dev |
| LOW | CVE-2005-0406 | A design flaw in image processing software that modifies JPEG images m ... | libmagickwand-dev |
| LOW | CVE-2008-3134 | GraphicsMagick/ImageMagick: multiple crash or DoS issues | libmagickwand-dev |
| LOW | CVE-2016-8678 | ImageMagick: Heap-buffer overflow in IsPixelMonochrome | libmagickwand-dev |
| LOW | CVE-2017-11754 | ImageMagick: Memory leak in WritePICONImage function | libmagickwand-dev |
| LOW | CVE-2017-11755 | ImageMagick: Memory leak in WritePICONImage function via mishandled AcquireSemaphoreInfo call | libmagickwand-dev |
| LOW | CVE-2017-7275 | ImageMagick: Memory allocation failure in AcquireMagickMemory (incomplete fix for  CVE-2016-8866) | libmagickwand-dev |
| LOW | CVE-2018-15607 | ImageMagick: CPU Exhaustion via crafted input file | libmagickwand-dev |
| LOW | CVE-2021-20311 | ImageMagick: Division by zero in sRGBTransformImage() in MagickCore/colorspace.c | libmagickwand-dev |
| LOW | CVE-2023-34152 | ImageMagick: RCE (shell command injection) vulnerability in OpenBlob with --enable-pipes configured | libmagickwand-dev |
| MEDIUM | CVE-2024-21096 | mysql: Client: mysqldump unspecified vulnerability (CPU Apr 2024) | libmariadb-dev |
| MEDIUM | CVE-2024-21096 | mysql: Client: mysqldump unspecified vulnerability (CPU Apr 2024) | libmariadb-dev-compat |
| MEDIUM | CVE-2024-21096 | mysql: Client: mysqldump unspecified vulnerability (CPU Apr 2024) | libmariadb3 |
| LOW | CVE-2022-0563 | util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline | libmount-dev |
| LOW | CVE-2022-0563 | util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline | libmount1 |
| MEDIUM | CVE-2023-50495 | ncurses: segmentation fault via _nc_wrap_entry() | libncurses-dev |
| MEDIUM | CVE-2023-50495 | ncurses: segmentation fault via _nc_wrap_entry() | libncurses5-dev |
| MEDIUM | CVE-2023-50495 | ncurses: segmentation fault via _nc_wrap_entry() | libncurses6 |
| MEDIUM | CVE-2023-50495 | ncurses: segmentation fault via _nc_wrap_entry() | libncursesw5-dev |
| MEDIUM | CVE-2023-50495 | ncurses: segmentation fault via _nc_wrap_entry() | libncursesw6 |
| CRITICAL | CVE-2023-5841 | OpenEXR: Heap Overflow in Scanline Deep Data Parsing | libopenexr-3-1-30 |
| LOW | CVE-2017-14988 | OpenEXR: Excessive memory allocation in Header::readfrom | libopenexr-3-1-30 |
| UNKNOWN | CVE-2024-31047 | An issue in Academy Software Foundation openexr v.3.2.3 and before all ... | libopenexr-3-1-30 |
| CRITICAL | CVE-2023-5841 | OpenEXR: Heap Overflow in Scanline Deep Data Parsing | libopenexr-dev |
| LOW | CVE-2017-14988 | OpenEXR: Excessive memory allocation in Header::readfrom | libopenexr-dev |
| UNKNOWN | CVE-2024-31047 | An issue in Academy Software Foundation openexr v.3.2.3 and before all ... | libopenexr-dev |
| MEDIUM | CVE-2023-39328 | openjpeg: denail of service via crafted image file | libopenjp2-7 |
| MEDIUM | CVE-2023-39329 | openjpeg: Resource exhaustion will occur in the opj_t1_decode_cblks function in the tcd.c | libopenjp2-7 |
| LOW | CVE-2016-10505 | openjpeg: NULL pointer dereference in imagetopnm function in convert.c | libopenjp2-7 |
| LOW | CVE-2016-9113 | openjpeg2: Multiple security issues | libopenjp2-7 |
| LOW | CVE-2016-9114 | openjpeg2: Multiple security issues | libopenjp2-7 |
| LOW | CVE-2016-9115 | openjpeg2: Multiple security issues | libopenjp2-7 |
| LOW | CVE-2016-9116 | openjpeg2: Multiple security issues | libopenjp2-7 |
| LOW | CVE-2016-9117 | openjpeg2: Multiple security issues | libopenjp2-7 |
| LOW | CVE-2016-9580 | openjpeg2: Integer overflow in tiftoimage causes heap buffer overflow | libopenjp2-7 |
| LOW | CVE-2016-9581 | openjpeg2: Infinite loop in tiftoimage resulting into heap buffer overflow in convert_32s_C1P1 | libopenjp2-7 |
| LOW | CVE-2017-17479 | openjpeg: Stack-buffer overflow in the pgxtoimage function | libopenjp2-7 |
| LOW | CVE-2018-16375 | openjpeg: Heap-based buffer overflow in pnmtoimage function in bin/jpwl/convert.c | libopenjp2-7 |
| LOW | CVE-2018-16376 | openjpeg: Heap-based buffer overflow in function t2_encode_packet in src/lib/openmj2/t2.c | libopenjp2-7 |
| LOW | CVE-2018-20846 | openjpeg: out-of-bounds read in functions pi_next_lrcp, pi_next_rlcp, pi_next_rpcl, pi_next_pcrl, pi_next_rpcl, and pi_next_cprl in openmj2/pi.c leads to denial of service | libopenjp2-7 |
| LOW | CVE-2019-6988 | openjpeg: DoS via memory exhaustion in opj_decompress | libopenjp2-7 |
| MEDIUM | CVE-2023-39328 | openjpeg: denail of service via crafted image file | libopenjp2-7-dev |
| MEDIUM | CVE-2023-39329 | openjpeg: Resource exhaustion will occur in the opj_t1_decode_cblks function in the tcd.c | libopenjp2-7-dev |
| LOW | CVE-2016-10505 | openjpeg: NULL pointer dereference in imagetopnm function in convert.c | libopenjp2-7-dev |
| LOW | CVE-2016-9113 | openjpeg2: Multiple security issues | libopenjp2-7-dev |
| LOW | CVE-2016-9114 | openjpeg2: Multiple security issues | libopenjp2-7-dev |
| LOW | CVE-2016-9115 | openjpeg2: Multiple security issues | libopenjp2-7-dev |
| LOW | CVE-2016-9116 | openjpeg2: Multiple security issues | libopenjp2-7-dev |
| LOW | CVE-2016-9117 | openjpeg2: Multiple security issues | libopenjp2-7-dev |
| LOW | CVE-2016-9580 | openjpeg2: Integer overflow in tiftoimage causes heap buffer overflow | libopenjp2-7-dev |
| LOW | CVE-2016-9581 | openjpeg2: Infinite loop in tiftoimage resulting into heap buffer overflow in convert_32s_C1P1 | libopenjp2-7-dev |
| LOW | CVE-2017-17479 | openjpeg: Stack-buffer overflow in the pgxtoimage function | libopenjp2-7-dev |
| LOW | CVE-2018-16375 | openjpeg: Heap-based buffer overflow in pnmtoimage function in bin/jpwl/convert.c | libopenjp2-7-dev |
| LOW | CVE-2018-16376 | openjpeg: Heap-based buffer overflow in function t2_encode_packet in src/lib/openmj2/t2.c | libopenjp2-7-dev |
| LOW | CVE-2018-20846 | openjpeg: out-of-bounds read in functions pi_next_lrcp, pi_next_rlcp, pi_next_rpcl, pi_next_pcrl, pi_next_rpcl, and pi_next_cprl in openmj2/pi.c leads to denial of service | libopenjp2-7-dev |
| LOW | CVE-2019-6988 | openjpeg: DoS via memory exhaustion in opj_decompress | libopenjp2-7-dev |
| MEDIUM | CVE-2024-10041 | pam: libpam: Libpam vulnerable to read hashed password | libpam-modules |
| MEDIUM | CVE-2024-22365 | pam: allowing unprivileged user to block another user namespace | libpam-modules |
| MEDIUM | CVE-2024-10041 | pam: libpam: Libpam vulnerable to read hashed password | libpam-modules-bin |
| MEDIUM | CVE-2024-22365 | pam: allowing unprivileged user to block another user namespace | libpam-modules-bin |
| MEDIUM | CVE-2024-10041 | pam: libpam: Libpam vulnerable to read hashed password | libpam-runtime |
| MEDIUM | CVE-2024-22365 | pam: allowing unprivileged user to block another user namespace | libpam-runtime |
| MEDIUM | CVE-2024-10041 | pam: libpam: Libpam vulnerable to read hashed password | libpam0g |
| MEDIUM | CVE-2024-22365 | pam: allowing unprivileged user to block another user namespace | libpam0g |
| HIGH | CVE-2023-31484 | perl: CPAN.pm does not verify TLS certificates when downloading distributions over HTTPS | libperl5.36 |
| LOW | CVE-2011-4116 | perl: File:: Temp insecure temporary file handling | libperl5.36 |
| LOW | CVE-2023-31486 | http-tiny: insecure TLS cert default | libperl5.36 |
| LOW | CVE-2023-37769 | stress-test master commit e4c878 was discovered to contain a FPE vulne ... | libpixman-1-0 |
| LOW | CVE-2023-37769 | stress-test master commit e4c878 was discovered to contain a FPE vulne ... | libpixman-1-dev |
| LOW | CVE-2021-4214 | libpng: hardcoded value leads to heap-overflow | libpng-dev |
| LOW | CVE-2021-4214 | libpng: hardcoded value leads to heap-overflow | libpng16-16 |
| LOW | CVE-2023-4016 | procps: ps buffer overflow | libproc2-0 |
| MEDIUM | CVE-2025-0938 | python: cpython: URL parser allowed square brackets in domain names | libpython3.11-minimal |
| MEDIUM | CVE-2025-0938 | python: cpython: URL parser allowed square brackets in domain names | libpython3.11-stdlib |
| LOW | CVE-2022-27943 | binutils: libiberty/rust-demangle.c in GNU GCC 11.2 allows stack exhaustion in demangle_const | libquadmath0 |
| LOW | CVE-2023-4039 | gcc: -fstack-protector fails to guard dynamic stack allocations on ARM64 | libquadmath0 |
| LOW | CVE-2022-0563 | util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline | libsmartcols1 |
| LOW | CVE-2021-45346 | sqlite: crafted SQL query allows a malicious user to obtain sensitive information | libsqlite3-0 |
| LOW | CVE-2021-45346 | sqlite: crafted SQL query allows a malicious user to obtain sensitive information | libsqlite3-dev |
| MEDIUM | CVE-2024-13176 | openssl: Timing side-channel in ECDSA signature computation | libssl-dev |
| MEDIUM | CVE-2024-13176 | openssl: Timing side-channel in ECDSA signature computation | libssl3 |
| LOW | CVE-2022-27943 | binutils: libiberty/rust-demangle.c in GNU GCC 11.2 allows stack exhaustion in demangle_const | libstdc++-12-dev |
| LOW | CVE-2023-4039 | gcc: -fstack-protector fails to guard dynamic stack allocations on ARM64 | libstdc++-12-dev |
| LOW | CVE-2022-27943 | binutils: libiberty/rust-demangle.c in GNU GCC 11.2 allows stack exhaustion in demangle_const | libstdc++6 |
| LOW | CVE-2023-4039 | gcc: -fstack-protector fails to guard dynamic stack allocations on ARM64 | libstdc++6 |
| LOW | CVE-2024-46901 | Subversion: Apache Subversion: mod_dav_svn denial-of-service via control characters in paths | libsvn1 |
| LOW | CVE-2013-4392 | systemd: TOCTOU race condition when updating file permissions and SELinux security contexts | libsystemd0 |
| LOW | CVE-2023-31437 | An issue was discovered in systemd 253. An attacker can modify a seale ... | libsystemd0 |
| LOW | CVE-2023-31438 | An issue was discovered in systemd 253. An attacker can truncate a sea ... | libsystemd0 |
| LOW | CVE-2023-31439 | An issue was discovered in systemd 253. An attacker can modify the con ... | libsystemd0 |
| UNKNOWN | CVE-2024-12133 | null | libtasn1-6 |
| LOW | CVE-2021-35331 | In Tcl 8.6.11, a format string vulnerability in nmakehlp.c might allow ... | libtcl8.6 |
| HIGH | CVE-2023-52355 | libtiff: TIFFRasterScanlineSize64 produce too-big size and could cause OOM | libtiff-dev |
| MEDIUM | CVE-2023-6277 | libtiff: Out-of-memory in TIFFOpen via a craft file | libtiff-dev |
| LOW | CVE-2017-16232 | libtiff: Memory leaks in tif_open.c, tif_lzw.c, and tif_aux.c | libtiff-dev |
| LOW | CVE-2017-17973 | libtiff: heap-based use after free in tiff2pdf.c:t2p_writeproc | libtiff-dev |
| LOW | CVE-2017-5563 | libtiff: Heap-buffer overflow in LZWEncode tif_lzw.c | libtiff-dev |
| LOW | CVE-2017-9117 | libtiff: Heap-based buffer over-read in bmp2tiff | libtiff-dev |
| LOW | CVE-2018-10126 | libtiff: NULL pointer dereference in the jpeg_fdct_16x16 function in jfdctint.c | libtiff-dev |
| LOW | CVE-2022-1210 | tiff: Malicious file leads to a denial of service in TIFF File Handler | libtiff-dev |
| LOW | CVE-2023-1916 | libtiff: out-of-bounds read in extractImageSection() in tools/tiffcrop.c | libtiff-dev |
| LOW | CVE-2023-3164 | libtiff: heap-buffer-overflow in extractImageSection() | libtiff-dev |
| LOW | CVE-2023-6228 | libtiff: heap-based buffer overflow in cpStripToTile() in tools/tiffcp.c | libtiff-dev |
| HIGH | CVE-2023-52355 | libtiff: TIFFRasterScanlineSize64 produce too-big size and could cause OOM | libtiff6 |
| MEDIUM | CVE-2023-6277 | libtiff: Out-of-memory in TIFFOpen via a craft file | libtiff6 |
| LOW | CVE-2017-16232 | libtiff: Memory leaks in tif_open.c, tif_lzw.c, and tif_aux.c | libtiff6 |
| LOW | CVE-2017-17973 | libtiff: heap-based use after free in tiff2pdf.c:t2p_writeproc | libtiff6 |
| LOW | CVE-2017-5563 | libtiff: Heap-buffer overflow in LZWEncode tif_lzw.c | libtiff6 |
| LOW | CVE-2017-9117 | libtiff: Heap-based buffer over-read in bmp2tiff | libtiff6 |
| LOW | CVE-2018-10126 | libtiff: NULL pointer dereference in the jpeg_fdct_16x16 function in jfdctint.c | libtiff6 |
| LOW | CVE-2022-1210 | tiff: Malicious file leads to a denial of service in TIFF File Handler | libtiff6 |
| LOW | CVE-2023-1916 | libtiff: out-of-bounds read in extractImageSection() in tools/tiffcrop.c | libtiff6 |
| LOW | CVE-2023-3164 | libtiff: heap-buffer-overflow in extractImageSection() | libtiff6 |
| LOW | CVE-2023-6228 | libtiff: heap-based buffer overflow in cpStripToTile() in tools/tiffcp.c | libtiff6 |
| HIGH | CVE-2023-52355 | libtiff: TIFFRasterScanlineSize64 produce too-big size and could cause OOM | libtiffxx6 |
| MEDIUM | CVE-2023-6277 | libtiff: Out-of-memory in TIFFOpen via a craft file | libtiffxx6 |
| LOW | CVE-2017-16232 | libtiff: Memory leaks in tif_open.c, tif_lzw.c, and tif_aux.c | libtiffxx6 |
| LOW | CVE-2017-17973 | libtiff: heap-based use after free in tiff2pdf.c:t2p_writeproc | libtiffxx6 |
| LOW | CVE-2017-5563 | libtiff: Heap-buffer overflow in LZWEncode tif_lzw.c | libtiffxx6 |
| LOW | CVE-2017-9117 | libtiff: Heap-based buffer over-read in bmp2tiff | libtiffxx6 |
| LOW | CVE-2018-10126 | libtiff: NULL pointer dereference in the jpeg_fdct_16x16 function in jfdctint.c | libtiffxx6 |
| LOW | CVE-2022-1210 | tiff: Malicious file leads to a denial of service in TIFF File Handler | libtiffxx6 |
| LOW | CVE-2023-1916 | libtiff: out-of-bounds read in extractImageSection() in tools/tiffcrop.c | libtiffxx6 |
| LOW | CVE-2023-3164 | libtiff: heap-buffer-overflow in extractImageSection() | libtiffxx6 |
| LOW | CVE-2023-6228 | libtiff: heap-based buffer overflow in cpStripToTile() in tools/tiffcp.c | libtiffxx6 |
| MEDIUM | CVE-2023-50495 | ncurses: segmentation fault via _nc_wrap_entry() | libtinfo6 |
| LOW | CVE-2022-27943 | binutils: libiberty/rust-demangle.c in GNU GCC 11.2 allows stack exhaustion in demangle_const | libtsan2 |
| LOW | CVE-2023-4039 | gcc: -fstack-protector fails to guard dynamic stack allocations on ARM64 | libtsan2 |
| LOW | CVE-2022-27943 | binutils: libiberty/rust-demangle.c in GNU GCC 11.2 allows stack exhaustion in demangle_const | libubsan1 |
| LOW | CVE-2023-4039 | gcc: -fstack-protector fails to guard dynamic stack allocations on ARM64 | libubsan1 |
| LOW | CVE-2013-4392 | systemd: TOCTOU race condition when updating file permissions and SELinux security contexts | libudev1 |
| LOW | CVE-2023-31437 | An issue was discovered in systemd 253. An attacker can modify a seale ... | libudev1 |
| LOW | CVE-2023-31438 | An issue was discovered in systemd 253. An attacker can truncate a sea ... | libudev1 |
| LOW | CVE-2023-31439 | An issue was discovered in systemd 253. An attacker can modify the con ... | libudev1 |
| LOW | CVE-2022-0563 | util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline | libuuid1 |
| LOW | CVE-2007-3476 | libgd Denial of service by corrupted GIF images | libwmf-0.2-7 |
| LOW | CVE-2007-3477 | gd: arc drawing functions can consume large amount of CPU time | libwmf-0.2-7 |
| LOW | CVE-2007-3996 | php multiple integer overflows in gd | libwmf-0.2-7 |
| LOW | CVE-2009-3546 | gd: insufficient input validation in _gdGetColors() | libwmf-0.2-7 |
| LOW | TEMP-0601525-BEBB65 | [libgd2: gdImageColorTransparent can write outside buffer] | libwmf-0.2-7 |
| LOW | CVE-2007-3476 | libgd Denial of service by corrupted GIF images | libwmf-dev |
| LOW | CVE-2007-3477 | gd: arc drawing functions can consume large amount of CPU time | libwmf-dev |
| LOW | CVE-2007-3996 | php multiple integer overflows in gd | libwmf-dev |
| LOW | CVE-2009-3546 | gd: insufficient input validation in _gdGetColors() | libwmf-dev |
| LOW | TEMP-0601525-BEBB65 | [libgd2: gdImageColorTransparent can write outside buffer] | libwmf-dev |
| LOW | CVE-2007-3476 | libgd Denial of service by corrupted GIF images | libwmflite-0.2-7 |
| LOW | CVE-2007-3477 | gd: arc drawing functions can consume large amount of CPU time | libwmflite-0.2-7 |
| LOW | CVE-2007-3996 | php multiple integer overflows in gd | libwmflite-0.2-7 |
| LOW | CVE-2009-3546 | gd: insufficient input validation in _gdGetColors() | libwmflite-0.2-7 |
| LOW | TEMP-0601525-BEBB65 | [libgd2: gdImageColorTransparent can write outside buffer] | libwmflite-0.2-7 |
| HIGH | CVE-2022-49043 | libxml: use-after-free in xmlXIncludeAddNode | libxml2 |
| HIGH | CVE-2024-25062 | libxml2: use-after-free in XMLReader | libxml2 |
| MEDIUM | CVE-2023-39615 | libxml2: crafted xml can cause global buffer overflow | libxml2 |
| MEDIUM | CVE-2023-45322 | libxml2: use-after-free in xmlUnlinkNode() in tree.c | libxml2 |
| LOW | CVE-2024-34459 | libxml2: buffer over-read in xmlHTMLPrintFileContext in xmllint.c | libxml2 |
| HIGH | CVE-2022-49043 | libxml: use-after-free in xmlXIncludeAddNode | libxml2-dev |
| HIGH | CVE-2024-25062 | libxml2: use-after-free in XMLReader | libxml2-dev |
| MEDIUM | CVE-2023-39615 | libxml2: crafted xml can cause global buffer overflow | libxml2-dev |
| MEDIUM | CVE-2023-45322 | libxml2: use-after-free in xmlUnlinkNode() in tree.c | libxml2-dev |
| LOW | CVE-2024-34459 | libxml2: buffer over-read in xmlHTMLPrintFileContext in xmllint.c | libxml2-dev |
| LOW | CVE-2015-9019 | libxslt: math.random() in xslt uses unseeded randomness | libxslt1-dev |
| LOW | CVE-2015-9019 | libxslt: math.random() in xslt uses unseeded randomness | libxslt1.1 |
| HIGH | CVE-2013-7445 | kernel: memory exhaustion via crafted Graphics Execution Manager (GEM) objects | linux-libc-dev |
| HIGH | CVE-2019-19449 | kernel: mounting a crafted f2fs filesystem image can lead to slab-out-of-bounds read access in f2fs_build_segment_manager in fs/f2fs/segment.c | linux-libc-dev |
| HIGH | CVE-2019-19814 | kernel: out-of-bounds write in __remove_dirty_segment in fs/f2fs/segment.c | linux-libc-dev |
| HIGH | CVE-2021-3847 | kernel: low-privileged user privileges escalation | linux-libc-dev |
| HIGH | CVE-2021-3864 | kernel: descendant's dumpable setting with certain SUID binaries | linux-libc-dev |
| HIGH | CVE-2023-52452 | kernel: bpf: Fix accesses to uninit stack slots | linux-libc-dev |
| HIGH | CVE-2023-52590 | kernel: ocfs2: Avoid touching renamed directory if parent does not change | linux-libc-dev |
| HIGH | CVE-2023-52751 | kernel: smb: client: fix use-after-free in smb2_query_info_compound() | linux-libc-dev |
| HIGH | CVE-2024-21803 | kernel: bluetooth: use-after-free vulnerability in af_bluetooth.c | linux-libc-dev |
| HIGH | CVE-2024-25742 | hw: amd: Instruction raise #VC exception at exit | linux-libc-dev |
| HIGH | CVE-2024-25743 | hw: amd: Instruction raise #VC exception at exit | linux-libc-dev |
| HIGH | CVE-2024-26669 | kernel: net/sched: flower: Fix chain template offload | linux-libc-dev |
| HIGH | CVE-2024-26739 | kernel: net/sched: act_mirred: don't override retval if we already lost the skb | linux-libc-dev |
| HIGH | CVE-2024-26913 | kernel: drm/amd/display: Fix dcn35 8k30 Underflow/Corruption Issue | linux-libc-dev |
| HIGH | CVE-2024-26930 | kernel: scsi: qla2xxx: Fix double free of the ha-&gt;vp_map pointer | linux-libc-dev |
| HIGH | CVE-2024-26944 | kernel: btrfs: zoned: fix use-after-free in do_zone_finish() | linux-libc-dev |
| HIGH | CVE-2024-27042 | kernel: drm/amdgpu: Fix potential out-of-bounds access in &#39;amdgpu_discovery_reg_base_init()&#39; | linux-libc-dev |
| HIGH | CVE-2024-35866 | kernel: smb: client: fix potential UAF in cifs_dump_full_key() | linux-libc-dev |
| HIGH | CVE-2024-35887 | kernel: ax25: fix use-after-free bugs caused by ax25_ds_del_timer | linux-libc-dev |
| HIGH | CVE-2024-35929 | kernel: rcu/nocb: Fix WARN_ON_ONCE() in the rcu_nocb_bypass_lock() | linux-libc-dev |
| HIGH | CVE-2024-36013 | kernel: Bluetooth: L2CAP: Fix slab-use-after-free in l2cap_connect() | linux-libc-dev |
| HIGH | CVE-2024-36899 | kernel: gpiolib: cdev: Fix use after free in lineinfo_changed_notify | linux-libc-dev |
| HIGH | CVE-2024-38570 | kernel: gfs2: Fix potential glock use-after-free on unmount | linux-libc-dev |
| HIGH | CVE-2024-38630 | kernel: watchdog: cpu5wdt.c: Fix use-after-free bug caused by cpu5wdt_trigger | linux-libc-dev |
| HIGH | CVE-2024-39479 | kernel: drm/i915/hwmon: Get rid of devm | linux-libc-dev |
| HIGH | CVE-2024-39508 | kernel: io_uring/io-wq: Use set_bit() and test_bit() at worker->flags | linux-libc-dev |
| HIGH | CVE-2024-41013 | kernel: xfs: don&#39;t walk off the end of a directory data block | linux-libc-dev |
| HIGH | CVE-2024-42162 | kernel: gve: Account for stopped queues when reading NIC stats | linux-libc-dev |
| HIGH | CVE-2024-44941 | kernel: f2fs: fix to cover read extent cache access with lock | linux-libc-dev |
| HIGH | CVE-2024-44942 | kernel: f2fs: fix to do sanity check on F2FS_INLINE_DATA flag in inode during GC | linux-libc-dev |
| HIGH | CVE-2024-44951 | kernel: serial: sc16is7xx: fix TX fifo corruption | linux-libc-dev |
| HIGH | CVE-2024-46774 | kernel: powerpc/rtas: Prevent Spectre v1 gadget construction in sys_rtas() | linux-libc-dev |
| HIGH | CVE-2024-46786 | kernel: fscache: delete fscache_cookie_lru_timer when fscache exits to avoid UAF | linux-libc-dev |
| HIGH | CVE-2024-46811 | kernel: drm/amd/display: Fix index may exceed array range within fpu_update_bw_bounding_box | linux-libc-dev |
| HIGH | CVE-2024-46813 | kernel: drm/amd/display: Check link_index before accessing dc-&gt;links[] | linux-libc-dev |
| HIGH | CVE-2024-46833 | kernel: net: hns3: void array out of bound when loop tnl_num | linux-libc-dev |
| HIGH | CVE-2024-47691 | kernel: f2fs: fix to avoid use-after-free in f2fs_stop_gc_thread() | linux-libc-dev |
| HIGH | CVE-2024-49928 | kernel: wifi: rtw89: avoid reading out of bounds when loading TX power FW elements | linux-libc-dev |
| HIGH | CVE-2024-49989 | kernel: drm/amd/display: fix double free issue during amdgpu module unload | linux-libc-dev |
| HIGH | CVE-2024-50029 | kernel: Bluetooth: hci_conn: Fix UAF in hci_enhanced_setup_sync | linux-libc-dev |
| HIGH | CVE-2024-50047 | kernel: smb: client: fix UAF in async decryption | linux-libc-dev |
| HIGH | CVE-2024-50061 | kernel: i3c: master: cdns: Fix use after free vulnerability in cdns_i3c_master Driver Due to Race Condition | linux-libc-dev |
| HIGH | CVE-2024-50063 | kernel: bpf: Prevent tail call between progs attached to different hooks | linux-libc-dev |
| HIGH | CVE-2024-50112 | kernel: x86/lam: Disable ADDRESS_MASKING in most cases | linux-libc-dev |
| HIGH | CVE-2024-50164 | kernel: bpf: Fix overloading of MEM_UNINIT's meaning | linux-libc-dev |
| HIGH | CVE-2024-50217 | kernel: btrfs: fix use-after-free of block device file in __btrfs_free_extra_devids() | linux-libc-dev |
| HIGH | CVE-2024-50226 | kernel: cxl/port: Fix use-after-free, permit out-of-order decoder shutdown | linux-libc-dev |
| HIGH | CVE-2024-50246 | kernel: fs/ntfs3: Add rough attr alloc_size check | linux-libc-dev |
| HIGH | CVE-2024-53068 | kernel: firmware: arm_scmi: Fix slab-use-after-free in scmi_bus_notifier() | linux-libc-dev |
| HIGH | CVE-2024-53108 | kernel: drm/amd/display: Adjust VSDB parser for replay feature | linux-libc-dev |
| HIGH | CVE-2024-53133 | kernel: drm/amd/display: Handle dml allocation failure to avoid crash | linux-libc-dev |
| HIGH | CVE-2024-53166 | kernel: block, bfq: fix bfqq uaf in bfq_limit_depth() | linux-libc-dev |
| HIGH | CVE-2024-53168 | kernel: sunrpc: fix one UAF issue caused by sunrpc kernel tcp socket | linux-libc-dev |
| HIGH | CVE-2024-53170 | kernel: block: fix uaf for flush rq while iterating tags | linux-libc-dev |
| HIGH | CVE-2024-53179 | kernel: smb: client: fix use-after-free of signing key | linux-libc-dev |
| HIGH | CVE-2024-53203 | kernel: usb: typec: fix potential array underflow in ucsi_ccg_sync_control() | linux-libc-dev |
| HIGH | CVE-2024-53229 | kernel: RDMA/rxe: Fix the qp flush warnings in req | linux-libc-dev |
| HIGH | CVE-2024-56538 | kernel: drm: zynqmp_kms: Unplug DRM device before removal | linux-libc-dev |
| HIGH | CVE-2024-56551 | kernel: drm/amdgpu: fix usage slab after free | linux-libc-dev |
| HIGH | CVE-2024-56582 | kernel: btrfs: fix use-after-free in btrfs_encoded_read_endio() | linux-libc-dev |
| HIGH | CVE-2024-56608 | kernel: drm/amd/display: Fix out-of-bounds access in 'dcn21_link_encoder_create' | linux-libc-dev |
| HIGH | CVE-2024-56631 | kernel: scsi: sg: Fix slab-use-after-free read in sg_release() | linux-libc-dev |
| HIGH | CVE-2024-56664 | kernel: bpf, sockmap: Fix race between element replace and close() | linux-libc-dev |
| HIGH | CVE-2024-56759 | kernel: btrfs: fix use-after-free when COWing tree bock and tracing is enabled | linux-libc-dev |
| HIGH | CVE-2024-56775 | kernel: drm/amd/display: Fix handling of plane refcount | linux-libc-dev |
| HIGH | CVE-2024-56784 | kernel: drm/amd/display: Adding array index check to prevent memory corruption | linux-libc-dev |
| HIGH | CVE-2024-57887 | kernel: drm: adv7511: Fix use-after-free in adv7533_attach_dsi() | linux-libc-dev |
| HIGH | CVE-2024-57892 | kernel: ocfs2: fix slab-use-after-free due to dangling pointer dqi_priv | linux-libc-dev |
| HIGH | CVE-2024-57896 | kernel: btrfs: flush delalloc workers queue before stopping cleaner kthread during unmount | linux-libc-dev |
| HIGH | CVE-2024-57900 | kernel: ila: serialize calls to nf_register_net_hooks() | linux-libc-dev |
| HIGH | CVE-2024-57910 | kernel: iio: light: vcnl4035: fix information leak in triggered buffer | linux-libc-dev |
| HIGH | CVE-2024-57911 | kernel: iio: dummy: iio_simply_dummy_buffer: fix information leak in triggered buffer | linux-libc-dev |
| HIGH | CVE-2025-21631 | kernel: block, bfq: fix waker_bfqq UAF after bfq_split_bfqq() | linux-libc-dev |
| HIGH | CVE-2025-21647 | kernel: sched: sch_cake: add bounds checks to host bulk flow fairness counts | linux-libc-dev |
| HIGH | CVE-2025-21648 | kernel: netfilter: conntrack: clamp maximum hashtable size to INT_MAX | linux-libc-dev |
| HIGH | CVE-2025-21671 | kernel: zram: fix potential UAF of zram table | linux-libc-dev |
| HIGH | CVE-2025-21680 | kernel: pktgen: Avoid out-of-bounds access in get_imix_entries | linux-libc-dev |
| MEDIUM | CVE-2019-15213 | kernel: use-after-free caused by malicious USB device in drivers/media/usb/dvb-usb/dvb-usb-init.c | linux-libc-dev |
| MEDIUM | CVE-2019-16089 | kernel: Improper return check in nbd_genl_status function in drivers/block/nbd.c | linux-libc-dev |
| MEDIUM | CVE-2019-20794 | kernel: task processes not being properly ended could lead to resource exhaustion | linux-libc-dev |
| MEDIUM | CVE-2020-14304 | kernel: ethtool when reading eeprom of device could lead to memory leak | linux-libc-dev |
| MEDIUM | CVE-2020-36694 | kernel: netfilter: use-after-free in the packet processing context | linux-libc-dev |
| MEDIUM | CVE-2023-0597 | kernel: x86/mm: Randomize per-cpu entry area | linux-libc-dev |
| MEDIUM | CVE-2023-21264 | In multiple functions of mem_protect.c, there is a possible way to acc ... | linux-libc-dev |
| MEDIUM | CVE-2023-23005 | kernel: incorrect check for error case in the memory_tier_init | linux-libc-dev |
| MEDIUM | CVE-2023-31082 | kernel: sleeping function called from an invalid context in gsmld_write | linux-libc-dev |
| MEDIUM | CVE-2023-3397 | kernel: slab-use-after-free Write in txEnd due to race condition | linux-libc-dev |
| MEDIUM | CVE-2023-37454 | kernel: udf: use-after-free write in udf_close_lvid | linux-libc-dev |
| MEDIUM | CVE-2023-4010 | kernel: usb: hcd: malformed USB descriptor leads to infinite loop in usb_giveback_urb() | linux-libc-dev |
| MEDIUM | CVE-2023-4133 | kernel: cxgb4: use-after-free in ch_flower_stats_cb() | linux-libc-dev |
| MEDIUM | CVE-2023-52485 | kernel: drm/amd/display: Wake DMCUB before sending a command cause deadlock | linux-libc-dev |
| MEDIUM | CVE-2023-52586 | kernel: drm/msm/dpu: Add mutex lock in control vblank irq | linux-libc-dev |
| MEDIUM | CVE-2023-52591 | kernel: reiserfs: Avoid touching renamed directory if parent does not change | linux-libc-dev |
| MEDIUM | CVE-2023-52596 | kernel: sysctl: Fix out of bounds access for empty sysctl registers | linux-libc-dev |
| MEDIUM | CVE-2023-52624 | kernel: drm/amd/display: Wake DMCUB before executing GPINT commands | linux-libc-dev |
| MEDIUM | CVE-2023-52625 | kernel: drm/amd/display: Refactor DMCUB enter/exit idle interface | linux-libc-dev |
| MEDIUM | CVE-2023-52629 | kernel: sh: push-switch: Reorder cleanup operations to avoid use-after-free bug | linux-libc-dev |
| MEDIUM | CVE-2023-52648 | kernel: drm/vmwgfx: Unmap the surface before resetting it on a plane state | linux-libc-dev |
| MEDIUM | CVE-2023-52653 | kernel: SUNRPC: fix a memleak in gss_import_v2_context | linux-libc-dev |
| MEDIUM | CVE-2023-52658 | kernel: Revert &#34;net/mlx5: Block entering switchdev mode with ns inconsistency&#34; | linux-libc-dev |
| MEDIUM | CVE-2023-52671 | kernel: drm/amd/display: Fix hang/underflow when transitioning to ODM4:1 | linux-libc-dev |
| MEDIUM | CVE-2023-52673 | kernel: drm/amd/display: Fix a debugfs null pointer error | linux-libc-dev |
| MEDIUM | CVE-2023-52676 | kernel: bpf: Guard stack limits against 32bit overflow | linux-libc-dev |
| MEDIUM | CVE-2023-52761 | kernel: riscv: VMAP_STACK overflow detection thread-safe | linux-libc-dev |
| MEDIUM | CVE-2023-52770 | kernel: f2fs: split initial and dynamic conditions for extent_cache | linux-libc-dev |
| MEDIUM | CVE-2023-52771 | kernel: cxl/port: Fix delete_endpoint() vs parent unregistration race | linux-libc-dev |
| MEDIUM | CVE-2023-52797 | kernel: drivers: perf: Check find_first_bit() return value | linux-libc-dev |
| MEDIUM | CVE-2023-52857 | kernel: drm/mediatek: Fix coverity issue with unintentional integer overflow | linux-libc-dev |
| MEDIUM | CVE-2023-52888 | kernel: media: mediatek: vcodec: Only free buffer VA that is not NULL | linux-libc-dev |
| MEDIUM | CVE-2023-52920 | kernel: bpf: support non-r10 register spill/fill to/from stack in precision tracking | linux-libc-dev |
| MEDIUM | CVE-2023-6039 | kernel: use-after-free in drivers/net/usb/lan78xx.c in lan78xx_disconnect | linux-libc-dev |
| MEDIUM | CVE-2023-6240 | kernel: Marvin vulnerability side-channel leakage in the RSA decryption operation | linux-libc-dev |
| MEDIUM | CVE-2024-2193 | hw: Spectre-SRC that is Speculative Race Conditions (SRCs) for synchronization primitives similar like Spectre V1 with possibility to bypass software features (e.g., IPIs, high-precision timers, etc) | linux-libc-dev |
| MEDIUM | CVE-2024-24855 | kernel: Race condition in lpfc_unregister_fcf_rescan() in scsi/lpfc/lpfc_hbadisc.c | linux-libc-dev |
| MEDIUM | CVE-2024-24864 | A race condition was found in the Linux kernel's media/dvb-core in dvb ... | linux-libc-dev |
| MEDIUM | CVE-2024-25740 | kernel: memory leak in ubi driver | linux-libc-dev |
| MEDIUM | CVE-2024-26596 | In the Linux kernel, the following vulnerability has been resolved:  n ... | linux-libc-dev |
| MEDIUM | CVE-2024-26618 | hw: arm64/sme: Always exit sme_alloc() early with existing storage | linux-libc-dev |
| MEDIUM | CVE-2024-26647 | kernel: drm/amd/display: Fix late dereference 'dsc' check in 'link_set_dsc_pps_packet()' | linux-libc-dev |
| MEDIUM | CVE-2024-26648 | kernel: NULL check in edp_setup_replay() | linux-libc-dev |
| MEDIUM | CVE-2024-26656 | kernel: drm/amdgpu: use-after-free vulnerability | linux-libc-dev |
| MEDIUM | CVE-2024-26661 | kernel: drm/amd/display: Add NULL test for 'timing generator' in 'dcn21_set_pipe()' | linux-libc-dev |
| MEDIUM | CVE-2024-26662 | kernel: drm/amd/display: 'panel_cntl' could be null in 'dcn21_set_backlight_level()' | linux-libc-dev |
| MEDIUM | CVE-2024-26670 | kernel: arm64: entry: fix ARM64_WORKAROUND_SPECULATIVE_UNPRIV_LOAD | linux-libc-dev |
| MEDIUM | CVE-2024-26672 | kernel: drm/amdgpu: variable 'mca_funcs' dereferenced before NULL check in 'amdgpu_mca_smu_get_mca_entry()' | linux-libc-dev |
| MEDIUM | CVE-2024-26677 | kernel: rxrpc: Fix delayed ACKs to not set the reference serial number | linux-libc-dev |
| MEDIUM | CVE-2024-26691 | kernel: KVM: arm64: Fix circular locking dependency | linux-libc-dev |
| MEDIUM | CVE-2024-26719 | kernel: nouveau: offload fence uevents work to workqueue | linux-libc-dev |
| MEDIUM | CVE-2024-26740 | kernel: net/sched: act_mirred: use the backlog for mirred ingress | linux-libc-dev |
| MEDIUM | CVE-2024-26756 | kernel: md: Don't register sync_thread for reshape directly | linux-libc-dev |
| MEDIUM | CVE-2024-26757 | kernel: md: Don't ignore read-only array in md_check_recovery() | linux-libc-dev |
| MEDIUM | CVE-2024-26758 | kernel: md: Don't ignore suspended array in md_check_recovery() | linux-libc-dev |
| MEDIUM | CVE-2024-26767 | kernel: drm/amd/display: fixed integer types and null check locations | linux-libc-dev |
| MEDIUM | CVE-2024-26768 | kernel: LoongArch: Change acpi_core_pic[NR_CPUS] to acpi_core_pic[MAX_CORE_PIC] | linux-libc-dev |
| MEDIUM | CVE-2024-26783 | kernel: mm/vmscan: fix a bug calling wakeup_kswapd() with a wrong zone index | linux-libc-dev |
| MEDIUM | CVE-2024-26799 | kernel: ASoC: qcom: Fix uninitialized pointer dmactl | linux-libc-dev |
| MEDIUM | CVE-2024-26807 | kernel: spi: cadence-qspi: fix pointer reference in runtime PM hooks | linux-libc-dev |
| MEDIUM | CVE-2024-26822 | kernel: smb: client: set correct id, uid and cruid for multiuser automounts | linux-libc-dev |
| MEDIUM | CVE-2024-26836 | kernel: platform/x86: think-lmi: Fix password opcode ordering for workstations | linux-libc-dev |
| MEDIUM | CVE-2024-26841 | kernel: LoongArch: Update cpu_sibling_map when disabling nonboot CPUs | linux-libc-dev |
| MEDIUM | CVE-2024-26842 | kernel: scsi: ufs: core: Fix shift issue in ufshcd_clear_cmd() | linux-libc-dev |
| MEDIUM | CVE-2024-26866 | kernel: spi: lpspi: Avoid potential use-after-free in probe() | linux-libc-dev |
| MEDIUM | CVE-2024-26869 | kernel: f2fs: fix to truncate meta inode pages forcely | linux-libc-dev |
| MEDIUM | CVE-2024-26876 | kernel: drm/bridge: adv7511: fix crash on irq during probe | linux-libc-dev |
| MEDIUM | CVE-2024-26902 | kernel: perf: RISCV: Fix panic on pmu overflow handler | linux-libc-dev |
| MEDIUM | CVE-2024-26914 | kernel: drm/amd/display: fix incorrect mpc_combine array size | linux-libc-dev |
| MEDIUM | CVE-2024-26947 | kernel: ARM: 9359/1: flush: check if the folio is reserved for no-mapping addresses | linux-libc-dev |
| MEDIUM | CVE-2024-26948 | kernel: drm/amd/display: Add a dc_state NULL check in dc_state_release | linux-libc-dev |
| MEDIUM | CVE-2024-26953 | kernel: net: esp: fix bad handling of pages from page_pool | linux-libc-dev |
| MEDIUM | CVE-2024-26962 | kernel: dm-raid456, md/raid456: fix a deadlock for dm-raid456 while io concurrent with reshape | linux-libc-dev |
| MEDIUM | CVE-2024-26982 | kernel: Squashfs: check the inode number is not the invalid value of zero | linux-libc-dev |
| MEDIUM | CVE-2024-27005 | kernel: interconnect: Don&#39;t access req_list while it&#39;s being manipulated | linux-libc-dev |
| MEDIUM | CVE-2024-27010 | kernel: net/sched: Fix mirred deadlock on device recursion | linux-libc-dev |
| MEDIUM | CVE-2024-27011 | kernel: netfilter: nf_tables: fix memleak in map from abort path | linux-libc-dev |
| MEDIUM | CVE-2024-27012 | kernel: netfilter: nf_tables: restore set elements when delete set fails | linux-libc-dev |
| MEDIUM | CVE-2024-27041 | kernel: drm/amd/display: fix NULL checks for adev-&gt;dm.dc in amdgpu_dm_fini() | linux-libc-dev |
| MEDIUM | CVE-2024-27056 | kernel: wifi: iwlwifi: mvm: ensure offloading TID queue exists | linux-libc-dev |
| MEDIUM | CVE-2024-27057 | kernel: ASoC: SOF: ipc4-pcm: Workaround for crashed firmware on system suspend | linux-libc-dev |
| MEDIUM | CVE-2024-27062 | kernel: nouveau: lock the client object tree. | linux-libc-dev |
| MEDIUM | CVE-2024-27079 | kernel: iommu/vt-d: Fix NULL domain on device release | linux-libc-dev |
| MEDIUM | CVE-2024-27408 | kernel: dmaengine: dw-edma: eDMA: Add sync read before starting the DMA transfer in remote setup | linux-libc-dev |
| MEDIUM | CVE-2024-35784 | kernel: btrfs: fix deadlock with fiemap and extent locking | linux-libc-dev |
| MEDIUM | CVE-2024-35790 | kernel: usb: typec: altmodes/displayport: create sysfs nodes as driver&#39;s default device attribute group | linux-libc-dev |
| MEDIUM | CVE-2024-35794 | kernel: dm-raid: really frozen sync_thread during suspend | linux-libc-dev |
| MEDIUM | CVE-2024-35799 | kernel: drm/amd/display: Prevent crash when disable stream | linux-libc-dev |
| MEDIUM | CVE-2024-35808 | kernel: md/dm-raid: don&#39;t call md_reap_sync_thread() directly | linux-libc-dev |
| MEDIUM | CVE-2024-35843 | kernel: iommu/vt-d: Use device rbtree in iopf reporting path | linux-libc-dev |
| MEDIUM | CVE-2024-35860 | kernel: bpf: support deferring bpf_link dealloc to after RCU grace period | linux-libc-dev |
| MEDIUM | CVE-2024-35869 | kernel: smb: client: guarantee refcounted children from parent session | linux-libc-dev |
| MEDIUM | CVE-2024-35878 | kernel: of: module: prevent NULL pointer dereference in vsnprintf() | linux-libc-dev |
| MEDIUM | CVE-2024-35904 | kernel: selinux: avoid dereference of garbage after mount failure | linux-libc-dev |
| MEDIUM | CVE-2024-35924 | kernel: usb: typec: ucsi: Limit read size on v1.2 | linux-libc-dev |
| MEDIUM | CVE-2024-35931 | kernel: drm/amdgpu: Skip do PCI error slot reset during RAS recovery | linux-libc-dev |
| MEDIUM | CVE-2024-35942 | kernel: pmdomain: imx8mp-blk-ctrl: imx8mp_blk: Add fdcc clock to hdmimix domain | linux-libc-dev |
| MEDIUM | CVE-2024-35945 | kernel: net: phy: phy_device: Prevent nullptr exceptions on ISR | linux-libc-dev |
| MEDIUM | CVE-2024-35946 | kernel: wifi: rtw89: fix null pointer access when abort scan | linux-libc-dev |
| MEDIUM | CVE-2024-35949 | kernel: btrfs: make sure that WRITTEN is set on all metadata blocks | linux-libc-dev |
| MEDIUM | CVE-2024-35951 | kernel: drm/panfrost: Fix the error path in panfrost_mmu_map_fault_addr() | linux-libc-dev |
| MEDIUM | CVE-2024-35961 | kernel: net/mlx5: Register devlink first under devlink lock | linux-libc-dev |
| MEDIUM | CVE-2024-35974 | kernel: block: fix q-&gt;blkg_list corruption during disk rebind | linux-libc-dev |
| MEDIUM | CVE-2024-36022 | kernel: drm/amdgpu: Init zone device and drm client after mode-1 reset on reload | linux-libc-dev |
| MEDIUM | CVE-2024-36024 | kernel: drm/amd/display: Disable idle reallow as part of command/gpint execution | linux-libc-dev |
| MEDIUM | CVE-2024-36476 | kernel: RDMA/rtrs: Ensure 'ib_sge list' is accessible | linux-libc-dev |
| MEDIUM | CVE-2024-36881 | kernel: mm/userfaultfd: reset ptes when close() for wr-protected ones | linux-libc-dev |
| MEDIUM | CVE-2024-36903 | kernel: ipv6: Fix potential uninit-value access in __ip6_make_skb() | linux-libc-dev |
| MEDIUM | CVE-2024-36907 | kernel: SUNRPC: add a missing rpc_stat for TCP TLS | linux-libc-dev |
| MEDIUM | CVE-2024-36908 | kernel: blk-iocost: do not WARN if iocg was already offlined | linux-libc-dev |
| MEDIUM | CVE-2024-36911 | kernel: hv_netvsc: Don&#39;t free decrypted memory | linux-libc-dev |
| MEDIUM | CVE-2024-36913 | kernel: Drivers: hv: vmbus: Leak pages if set_memory_encrypted() fails | linux-libc-dev |
| MEDIUM | CVE-2024-36921 | kernel: wifi: iwlwifi: mvm: guard against invalid STA ID on removal | linux-libc-dev |
| MEDIUM | CVE-2024-36922 | kernel: wifi: iwlwifi: read txq-&gt;read_ptr under lock | linux-libc-dev |
| MEDIUM | CVE-2024-36927 | kernel: ipv4: Fix uninit-value access in __ip_make_skb() | linux-libc-dev |
| MEDIUM | CVE-2024-36949 | kernel: amd/amdkfd: sync all devices to wait all processes being evicted | linux-libc-dev |
| MEDIUM | CVE-2024-36951 | kernel: drm/amdkfd: range check cp bad op exception interrupts | linux-libc-dev |
| MEDIUM | CVE-2024-36968 | kernel: Bluetooth: L2CAP: Fix div-by-zero in l2cap_le_flowctl_init() | linux-libc-dev |
| MEDIUM | CVE-2024-38541 | kernel: of: module: add buffer overflow check in of_modalias() | linux-libc-dev |
| MEDIUM | CVE-2024-38557 | kernel: net/mlx5: Reload only IB representors upon lag disable/enable | linux-libc-dev |
| MEDIUM | CVE-2024-38564 | kernel: bpf: Add BPF_PROG_TYPE_CGROUP_SKB attach type enforcement in BPF_LINK_CREATE | linux-libc-dev |
| MEDIUM | CVE-2024-38594 | kernel: net: stmmac: move the EST lock to struct stmmac_priv | linux-libc-dev |
| MEDIUM | CVE-2024-38608 | kernel: net/mlx5e: Fix netif state handling | linux-libc-dev |
| MEDIUM | CVE-2024-38611 | kernel: media: i2c: et8ek8: Don&#39;t strip remove function when driver is builtin | linux-libc-dev |
| MEDIUM | CVE-2024-38620 | kernel: Bluetooth: HCI: Remove HCI_AMP support | linux-libc-dev |
| MEDIUM | CVE-2024-38622 | kernel: drm/msm/dpu: Add callback function pointer check before its call | linux-libc-dev |
| MEDIUM | CVE-2024-38625 | kernel: fs/ntfs3: Check &#39;folio&#39; pointer for NULL | linux-libc-dev |
| MEDIUM | CVE-2024-39282 | kernel: net: wwan: t7xx: Fix FSM command timeout issue | linux-libc-dev |
| MEDIUM | CVE-2024-39293 | kernel: Revert &#34;xsk: Support redirect to any socket bound to the same umem&#34; | linux-libc-dev |
| MEDIUM | CVE-2024-40945 | kernel: iommu: Return right value in iommu_sva_bind_device() | linux-libc-dev |
| MEDIUM | CVE-2024-40965 | kernel: i2c: lpi2c: Avoid calling clk_get_rate during transfer | linux-libc-dev |
| MEDIUM | CVE-2024-40969 | kernel: f2fs: don't set RO when shutting down f2fs | linux-libc-dev |
| MEDIUM | CVE-2024-40973 | kernel: media: mtk-vcodec: potential null pointer deference in SCP | linux-libc-dev |
| MEDIUM | CVE-2024-40975 | kernel: platform/x86: x86-android-tablets: Unregister devices in reverse order | linux-libc-dev |
| MEDIUM | CVE-2024-40982 | kernel: ssb: Fix potential NULL pointer dereference in ssb_device_uevent() | linux-libc-dev |
| MEDIUM | CVE-2024-40997 | kernel: cpufreq: amd-pstate: fix memory leak on CPU EPP exit | linux-libc-dev |
| MEDIUM | CVE-2024-40998 | kernel: ext4: fix uninitialized ratelimit_state-&gt;lock access in __ext4_fill_super() | linux-libc-dev |
| MEDIUM | CVE-2024-40999 | kernel: net: ena: Add validation for completion descriptors consistency | linux-libc-dev |
| MEDIUM | CVE-2024-41008 | kernel: drm/amdgpu: change vm-&gt;task_info handling | linux-libc-dev |
| MEDIUM | CVE-2024-41023 | kernel: sched/deadline: Fix task_struct reference leak | linux-libc-dev |
| MEDIUM | CVE-2024-41031 | kernel: mm/filemap: skip to create PMD-sized page cache if needed | linux-libc-dev |
| MEDIUM | CVE-2024-41045 | kernel: bpf: Defer work in bpf_timer_cancel_and_free | linux-libc-dev |
| MEDIUM | CVE-2024-41067 | kernel: btrfs: scrub: handle RST lookup error correctly | linux-libc-dev |
| MEDIUM | CVE-2024-41082 | kernel: nvme-fabrics: use reserved tag for reg read/write command | linux-libc-dev |
| MEDIUM | CVE-2024-41935 | kernel: f2fs: fix to shrink read extent node in batches | linux-libc-dev |
| MEDIUM | CVE-2024-42067 | kernel: bpf: Take return from set_memory_rox() into account with bpf_jit_binary_lock_ro() | linux-libc-dev |
| MEDIUM | CVE-2024-42079 | kernel: gfs2: Fix NULL pointer dereference in gfs2_log_flush | linux-libc-dev |
| MEDIUM | CVE-2024-42107 | kernel: ice: Don't process extts if PTP is disabled | linux-libc-dev |
| MEDIUM | CVE-2024-42118 | kernel: drm/amd/display: Do not return negative stream id for array | linux-libc-dev |
| MEDIUM | CVE-2024-42122 | kernel: drm/amd/display: Add NULL pointer check for kzalloc | linux-libc-dev |
| MEDIUM | CVE-2024-42123 | kernel: drm/amdgpu: fix double free err_addr pointer warnings | linux-libc-dev |
| MEDIUM | CVE-2024-42125 | kernel: wifi: rtw89: fw: scan offload prohibit all 6 GHz channel if no 6 GHz sband | linux-libc-dev |
| MEDIUM | CVE-2024-42128 | kernel: leds: an30259a: Use devm_mutex_init() for mutex initialization | linux-libc-dev |
| MEDIUM | CVE-2024-42129 | kernel: leds: mlxreg: Use devm_mutex_init() for mutex initialization | linux-libc-dev |
| MEDIUM | CVE-2024-42134 | kernel: virtio-pci: Check if is_avq is NULL | linux-libc-dev |
| MEDIUM | CVE-2024-42135 | kernel: vhost_task: Handle SIGKILL by flushing work and exiting | linux-libc-dev |
| MEDIUM | CVE-2024-42139 | kernel: ice: Fix improper extts handling | linux-libc-dev |
| MEDIUM | CVE-2024-42151 | kernel: bpf: mark bpf_dummy_struct_ops.test_1 parameter as nullable | linux-libc-dev |
| MEDIUM | CVE-2024-42156 | kernel: s390/pkey: Wipe copies of clear-key structures on failure | linux-libc-dev |
| MEDIUM | CVE-2024-42158 | kernel: s390/pkey: Use kfree_sensitive() to fix Coccinelle warnings | linux-libc-dev |
| MEDIUM | CVE-2024-42239 | kernel: bpf: Fail bpf_timer_cancel when callback is being cancelled | linux-libc-dev |
| MEDIUM | CVE-2024-42241 | kernel: mm/shmem: disable PMD-sized page cache if needed | linux-libc-dev |
| MEDIUM | CVE-2024-42243 | kernel: mm/filemap: make MAX_PAGECACHE_ORDER acceptable to xarray | linux-libc-dev |
| MEDIUM | CVE-2024-42279 | kernel: spi: microchip-core: ensure TX and RX FIFOs are empty at start of a transfer | linux-libc-dev |
| MEDIUM | CVE-2024-42317 | kernel: mm/huge_memory: avoid PMD-size page cache if needed | linux-libc-dev |
| MEDIUM | CVE-2024-43819 | kernel: kvm: s390: Reject memory region operations for ucontrol VMs | linux-libc-dev |
| MEDIUM | CVE-2024-43824 | kernel: PCI: endpoint: pci-epf-test: Make use of cached &#39;epc_features&#39; in pci_epf_test_core_init() | linux-libc-dev |
| MEDIUM | CVE-2024-43831 | kernel: media: mediatek: vcodec: Handle invalid decoder vsi | linux-libc-dev |
| MEDIUM | CVE-2024-43840 | kernel: bpf, arm64: Fix trampoline for BPF_TRAMP_F_CALL_ORIG | linux-libc-dev |
| MEDIUM | CVE-2024-43850 | kernel: soc: qcom: icc-bwmon: Fix refcount imbalance seen during bwmon_remove | linux-libc-dev |
| MEDIUM | CVE-2024-43872 | kernel: RDMA/hns: Fix soft lockup under heavy CEQE load | linux-libc-dev |
| MEDIUM | CVE-2024-43886 | kernel: drm/amd/display: Add null check in resource_log_pipe_topology_update | linux-libc-dev |
| MEDIUM | CVE-2024-43899 | kernel: drm/amd/display: Fix null pointer deref in dcn20_resource.c | linux-libc-dev |
| MEDIUM | CVE-2024-43901 | kernel: drm/amd/display: Fix NULL pointer dereference for DTN log in DCN401 | linux-libc-dev |
| MEDIUM | CVE-2024-43913 | kernel: nvme: apple: fix device reference counting | linux-libc-dev |
| MEDIUM | CVE-2024-44955 | kernel: drm/amd/display: Don't refer to dc_sink in is_dsc_need_re_compute | linux-libc-dev |
| MEDIUM | CVE-2024-44957 | kernel: xen: privcmd: Switch from mutex to spinlock for irqfds | linux-libc-dev |
| MEDIUM | CVE-2024-44961 | kernel: drm/amdgpu: Forward soft recovery errors to userspace | linux-libc-dev |
| MEDIUM | CVE-2024-44963 | kernel: btrfs: do not BUG_ON() when freeing tree block after error | linux-libc-dev |
| MEDIUM | CVE-2024-44972 | kernel: btrfs: do not clear page dirty inside extent_write_locked_range() | linux-libc-dev |
| MEDIUM | CVE-2024-45015 | kernel: drm/msm/dpu: move dpu_encoder&#39;s connector assignment to atomic_enable() | linux-libc-dev |
| MEDIUM | CVE-2024-46678 | kernel: bonding: change ipsec_lock from spin lock to mutex | linux-libc-dev |
| MEDIUM | CVE-2024-46681 | kernel: pktgen: use cpus_read_lock() in pg_net_init() | linux-libc-dev |
| MEDIUM | CVE-2024-46698 | kernel: video/aperture: optionally match the device in sysfb_disable() | linux-libc-dev |
| MEDIUM | CVE-2024-46727 | kernel: drm/amd/display: Add otg_master NULL check within resource_log_pipe_topology_update | linux-libc-dev |
| MEDIUM | CVE-2024-46728 | kernel: drm/amd/display: Check index for aux_rd_interval before using | linux-libc-dev |
| MEDIUM | CVE-2024-46729 | kernel: drm/amd/display: Fix incorrect size calculation for loop | linux-libc-dev |
| MEDIUM | CVE-2024-46730 | kernel: drm/amd/display: Ensure array index tg_inst won&#39;t be -1 | linux-libc-dev |
| MEDIUM | CVE-2024-46733 | kernel: btrfs: fix qgroup reserve leaks in cow_file_range | linux-libc-dev |
| MEDIUM | CVE-2024-46742 | kernel: smb/server: fix potential null-ptr-deref of lease_ctx_info in smb2_open() | linux-libc-dev |
| MEDIUM | CVE-2024-46748 | kernel: cachefiles: Set the max subreq size for cache writes to MAX_RW_COUNT | linux-libc-dev |
| MEDIUM | CVE-2024-46751 | kernel: btrfs: don&#39;t BUG_ON() when 0 reference count at btrfs_lookup_extent_info() | linux-libc-dev |
| MEDIUM | CVE-2024-46753 | kernel: btrfs: handle errors from btrfs_dec_ref() properly | linux-libc-dev |
| MEDIUM | CVE-2024-46754 | kernel: bpf: Remove tst_run from lwt_seg6local_prog_ops. | linux-libc-dev |
| MEDIUM | CVE-2024-46760 | kernel: wifi: rtw88: usb: schedule rx work after everything is set up | linux-libc-dev |
| MEDIUM | CVE-2024-46762 | kernel: xen: privcmd: Fix possible access to a freed kirqfd instance | linux-libc-dev |
| MEDIUM | CVE-2024-46765 | kernel: ice: protect XDP configuration with a mutex | linux-libc-dev |
| MEDIUM | CVE-2024-46772 | kernel: drm/amd/display: Check denominator crb_pipes before used | linux-libc-dev |
| MEDIUM | CVE-2024-46775 | kernel: drm/amd/display: Validate function returns | linux-libc-dev |
| MEDIUM | CVE-2024-46776 | kernel: drm/amd/display: Run DC_LOG_DC after checking link-&gt;link_enc | linux-libc-dev |
| MEDIUM | CVE-2024-46787 | kernel: userfaultfd: fix checks for huge PMDs | linux-libc-dev |
| MEDIUM | CVE-2024-46803 | kernel: drm/amdkfd: Check debug trap enable before write dbg_ev_file | linux-libc-dev |
| MEDIUM | CVE-2024-46806 | kernel: drm/amdgpu: Fix the warning division or modulo by zero | linux-libc-dev |
| MEDIUM | CVE-2024-46808 | kernel: drm/amd/display: Add missing NULL pointer check within dpcd_extend_address_range | linux-libc-dev |
| MEDIUM | CVE-2024-46816 | kernel: drm/amd/display: Stop amdgpu_dm initialize when link nums greater than max_links | linux-libc-dev |
| MEDIUM | CVE-2024-46823 | kernel: kunit/overflow: Fix UB in overflow_allocation_test | linux-libc-dev |
| MEDIUM | CVE-2024-46825 | kernel: wifi: iwlwifi: mvm: use IWL_FW_CHECK for link ID check | linux-libc-dev |
| MEDIUM | CVE-2024-46834 | kernel: ethtool: fail closed if we can&#39;t get max channel used in indirection tables | linux-libc-dev |
| MEDIUM | CVE-2024-46842 | kernel: scsi: lpfc: Handle mailbox timeouts in lpfc_get_sfp_info | linux-libc-dev |
| MEDIUM | CVE-2024-46843 | kernel: scsi: ufs: core: Remove SCSI host only if added | linux-libc-dev |
| MEDIUM | CVE-2024-46860 | kernel: wifi: mt76: mt7921: fix NULL pointer access in mt7921_ipv6_addr_change | linux-libc-dev |
| MEDIUM | CVE-2024-46861 | kernel: usbnet: ipheth: do not stop RX on failing RX callback | linux-libc-dev |
| MEDIUM | CVE-2024-46870 | kernel: drm/amd/display: Disable DMCUB timeout for DCN35 | linux-libc-dev |
| MEDIUM | CVE-2024-47141 | kernel: pinmux: Use sequential access to access desc->pinmux data | linux-libc-dev |
| MEDIUM | CVE-2024-47658 | kernel: crypto: stm32/cryp - call finalize with bh disabled | linux-libc-dev |
| MEDIUM | CVE-2024-47661 | kernel: drm/amd/display: Avoid overflow from uint32_t to uint8_t | linux-libc-dev |
| MEDIUM | CVE-2024-47662 | kernel: drm/amd/display: Remove register from DCN35 DMCUB diagnostic collection | linux-libc-dev |
| MEDIUM | CVE-2024-47664 | kernel: spi: hisi-kunpeng: Add verification for the max_frequency provided by the firmware | linux-libc-dev |
| MEDIUM | CVE-2024-47666 | kernel: scsi: pm80xx: Set phy-&gt;enable_completion only when we wait for it | linux-libc-dev |
| MEDIUM | CVE-2024-47703 | kernel: bpf, lsm: Add check for BPF LSM return value | linux-libc-dev |
| MEDIUM | CVE-2024-47704 | kernel: drm/amd/display: Check link_res-&gt;hpo_dp_link_enc before using it | linux-libc-dev |
| MEDIUM | CVE-2024-47726 | kernel: f2fs: fix to wait dio completion | linux-libc-dev |
| MEDIUM | CVE-2024-47736 | kernel: erofs: handle overlapped pclusters out of crafted images properly | linux-libc-dev |
| MEDIUM | CVE-2024-47752 | kernel: media: mediatek: vcodec: Fix H264 stateless decoder smatch warning | linux-libc-dev |
| MEDIUM | CVE-2024-47753 | kernel: media: mediatek: vcodec: Fix VP8 stateless decoder smatch warning | linux-libc-dev |
| MEDIUM | CVE-2024-47754 | kernel: media: mediatek: vcodec: Fix H264 multi stateless decoder smatch warning | linux-libc-dev |
| MEDIUM | CVE-2024-47794 | kernel: bpf: Prevent tailcall infinite loop caused by freplace | linux-libc-dev |
| MEDIUM | CVE-2024-47809 | kernel: dlm: fix possible lkb_resource null dereference | linux-libc-dev |
| MEDIUM | CVE-2024-48875 | kernel: btrfs: don't take dev_replace rwsem on task already holding it | linux-libc-dev |
| MEDIUM | CVE-2024-49568 | kernel: net/smc: check v2_ext_offset/eid_cnt/ism_gid_cnt when receiving proposal msg | linux-libc-dev |
| MEDIUM | CVE-2024-49569 | kernel: nvme-rdma: unquiesce admin_q before destroy it | linux-libc-dev |
| MEDIUM | CVE-2024-49893 | kernel: drm/amd/display: Check stream_status before it is used | linux-libc-dev |
| MEDIUM | CVE-2024-49901 | kernel: drm/msm/adreno: Assign msm_gpu-&gt;pdev earlier to avoid nullptrs | linux-libc-dev |
| MEDIUM | CVE-2024-49906 | kernel: drm/amd/display: Check null pointer before try to access it | linux-libc-dev |
| MEDIUM | CVE-2024-49908 | kernel: drm/amd/display: Add null check for &#39;afb&#39; in amdgpu_dm_update_cursor (v2) | linux-libc-dev |
| MEDIUM | CVE-2024-49910 | kernel: drm/amd/display: Add NULL check for function pointer in dcn401_set_output_transfer_func | linux-libc-dev |
| MEDIUM | CVE-2024-49914 | kernel: drm/amd/display: Add null check for pipe_ctx-&gt;plane_state in dcn20_program_pipe | linux-libc-dev |
| MEDIUM | CVE-2024-49916 | kernel: drm/amd/display: Add NULL check for clk_mgr and clk_mgr-&gt;funcs in dcn401_init_hw | linux-libc-dev |
| MEDIUM | CVE-2024-49918 | kernel: drm/amd/display: Add null check for head_pipe in dcn32_acquire_idle_pipe_for_head_pipe_in_layer | linux-libc-dev |
| MEDIUM | CVE-2024-49919 | kernel: drm/amd/display: Add null check for head_pipe in dcn201_acquire_free_pipe_for_layer | linux-libc-dev |
| MEDIUM | CVE-2024-49920 | kernel: drm/amd/display: Check null pointers before multiple uses | linux-libc-dev |
| MEDIUM | CVE-2024-49921 | kernel: drm/amd/display: Check null pointers before used | linux-libc-dev |
| MEDIUM | CVE-2024-49922 | kernel: drm/amd/display: Check null pointers before using them | linux-libc-dev |
| MEDIUM | CVE-2024-49923 | kernel: drm/amd/display: Pass non-null to dcn20_validate_apply_pipe_split_flags | linux-libc-dev |
| MEDIUM | CVE-2024-49926 | kernel: rcu-tasks: Fix access non-existent percpu rtpcp variable in rcu_tasks_need_gpcb() | linux-libc-dev |
| MEDIUM | CVE-2024-49932 | kernel: btrfs: don&#39;t readahead the relocation inode on RST | linux-libc-dev |
| MEDIUM | CVE-2024-49940 | kernel: l2tp: prevent possible tunnel refcount underflow | linux-libc-dev |
| MEDIUM | CVE-2024-49945 | kernel: net/ncsi: Disable the ncsi work before freeing the associated structure | linux-libc-dev |
| MEDIUM | CVE-2024-49968 | kernel: ext4: filesystems without casefold feature cannot be mounted with siphash | linux-libc-dev |
| MEDIUM | CVE-2024-49970 | kernel: drm/amd/display: Implement bounds check for stream encoder creation in DCN401 | linux-libc-dev |
| MEDIUM | CVE-2024-49972 | kernel: drm/amd/display: Deallocate DML memory if allocation fails | linux-libc-dev |
| MEDIUM | CVE-2024-49987 | kernel: bpftool: Fix undefined behavior in qsort(NULL, 0, ...) | linux-libc-dev |
| MEDIUM | CVE-2024-49988 | kernel: ksmbd: add refcnt to ksmbd_conn struct | linux-libc-dev |
| MEDIUM | CVE-2024-49994 | kernel: block: fix integer overflow in BLKSECDISCARD | linux-libc-dev |
| MEDIUM | CVE-2024-49998 | kernel: net: dsa: improve shutdown sequence | linux-libc-dev |
| MEDIUM | CVE-2024-50009 | kernel: cpufreq: amd-pstate: add check for cpufreq_cpu_get&#39;s return value | linux-libc-dev |
| MEDIUM | CVE-2024-50014 | kernel: ext4: fix access to uninitialised lock in fc replay path | linux-libc-dev |
| MEDIUM | CVE-2024-50016 | kernel: drm/amd/display: Avoid overflow assignment in link_dp_cts | linux-libc-dev |
| MEDIUM | CVE-2024-50017 | kernel: x86/mm/ident_map: Use gbpages only where full GB page should be mapped. | linux-libc-dev |
| MEDIUM | CVE-2024-50028 | kernel: thermal: core: Reference count the zone in thermal_zone_get_by_id() | linux-libc-dev |
| MEDIUM | CVE-2024-50032 | kernel: rcu/nocb: Fix rcuog wake-up from offline softirq | linux-libc-dev |
| MEDIUM | CVE-2024-50056 | kernel: usb: gadget: uvc: Fix ERR_PTR dereference in uvc_v4l2.c | linux-libc-dev |
| MEDIUM | CVE-2024-50111 | kernel: LoongArch: Enable IRQ if do_ale() triggered in irq-enabled context | linux-libc-dev |
| MEDIUM | CVE-2024-50135 | kernel: nvme-pci: fix race condition between reset and nvme_dev_disable() | linux-libc-dev |
| MEDIUM | CVE-2024-50166 | kernel: fsl/fman: Fix refcount handling of fman-related devices | linux-libc-dev |
| MEDIUM | CVE-2024-50277 | kernel: dm: fix a crash if blk_alloc_disk fails | linux-libc-dev |
| MEDIUM | CVE-2024-50285 | kernel: ksmbd: check outstanding simultaneous SMB operations | linux-libc-dev |
| MEDIUM | CVE-2024-50289 | kernel: media: av7110: fix a spectre vulnerability | linux-libc-dev |
| MEDIUM | CVE-2024-50298 | kernel: net: enetc: allocate vf_state during PF probes | linux-libc-dev |
| MEDIUM | CVE-2024-50304 | kernel: ipv4: ip_tunnel: Fix suspicious RCU usage warning in ip_tunnel_find() | linux-libc-dev |
| MEDIUM | CVE-2024-53050 | kernel: drm/i915/hdcp: Add encoder check in hdcp2_get_capability | linux-libc-dev |
| MEDIUM | CVE-2024-53051 | kernel: drm/i915/hdcp: Add encoder check in intel_hdcp_get_capability | linux-libc-dev |
| MEDIUM | CVE-2024-53056 | kernel: drm/mediatek: Fix potential NULL dereference in mtk_crtc_destroy() | linux-libc-dev |
| MEDIUM | CVE-2024-53079 | kernel: mm/thp: fix deferred split unqueue naming and locking | linux-libc-dev |
| MEDIUM | CVE-2024-53085 | kernel: tpm: Lock TPM chip in tpm_pm_suspend() first | linux-libc-dev |
| MEDIUM | CVE-2024-53089 | kernel: LoongArch: KVM: Mark hrtimer to expire in hard interrupt context | linux-libc-dev |
| MEDIUM | CVE-2024-53090 | kernel: afs: Fix lock recursion | linux-libc-dev |
| MEDIUM | CVE-2024-53091 | kernel: bpf: Add sk_is_inet and IS_ICSK check in tls_sw_has_ctx_tx/rx | linux-libc-dev |
| MEDIUM | CVE-2024-53094 | kernel: RDMA/siw: Add sendpage_ok() check to disable MSG_SPLICE_PAGES | linux-libc-dev |
| MEDIUM | CVE-2024-53095 | kernel: smb: client: Fix use-after-free of network namespace. | linux-libc-dev |
| MEDIUM | CVE-2024-53114 | kernel: x86/CPU/AMD: Clear virtualized VMLOAD/VMSAVE on Zen4 client | linux-libc-dev |
| MEDIUM | CVE-2024-53124 | kernel: net: fix data-races around sk->sk_forward_alloc | linux-libc-dev |
| MEDIUM | CVE-2024-53128 | kernel: sched/task_stack: fix object_is_on_stack() for KASAN tagged pointers | linux-libc-dev |
| MEDIUM | CVE-2024-53134 | kernel: pmdomain: imx93-blk-ctrl: correct remove path | linux-libc-dev |
| MEDIUM | CVE-2024-53147 | kernel: exfat: fix out-of-bounds access of directory entries | linux-libc-dev |
| MEDIUM | CVE-2024-53176 | kernel: smb: During unmount, ensure all cached dir instances drop their dentry | linux-libc-dev |
| MEDIUM | CVE-2024-53177 | kernel: smb: prevent use-after-free due to open_cached_dir error paths | linux-libc-dev |
| MEDIUM | CVE-2024-53178 | kernel: smb: Don't leak cfid when reconnect races with open_cached_dir | linux-libc-dev |
| MEDIUM | CVE-2024-53187 | kernel: io_uring: check for overflows in io_pin_pages | linux-libc-dev |
| MEDIUM | CVE-2024-53195 | kernel: KVM: arm64: Get rid of userspace_irqchip_in_use | linux-libc-dev |
| MEDIUM | CVE-2024-53209 | kernel: bnxt_en: Fix receive ring space parameters when XDP is active | linux-libc-dev |
| MEDIUM | CVE-2024-53216 | kernel: nfsd: release svc_expkey/svc_export with rcu_work | linux-libc-dev |
| MEDIUM | CVE-2024-53218 | kernel: f2fs: fix race in concurrent f2fs_stop_gc_thread | linux-libc-dev |
| MEDIUM | CVE-2024-53219 | kernel: virtiofs: use pages instead of pointer for kernel direct IO | linux-libc-dev |
| MEDIUM | CVE-2024-53221 | kernel: f2fs: fix null-ptr-deref in f2fs_submit_page_bio() | linux-libc-dev |
| MEDIUM | CVE-2024-53224 | kernel: RDMA/mlx5: Move events notifier registration to be after device registration | linux-libc-dev |
| MEDIUM | CVE-2024-53234 | kernel: erofs: handle NONHEAD !delta[1] lclusters gracefully | linux-libc-dev |
| MEDIUM | CVE-2024-53685 | kernel: ceph: give up on paths longer than PATH_MAX | linux-libc-dev |
| MEDIUM | CVE-2024-53687 | kernel: riscv: Fix IPIs usage in kfence_protect_page() | linux-libc-dev |
| MEDIUM | CVE-2024-54031 | kernel: netfilter: nft_set_hash: unaligned atomic read on struct nft_set_ext | linux-libc-dev |
| MEDIUM | CVE-2024-54683 | kernel: netfilter: IDLETIMER: Fix for possible ABBA deadlock | linux-libc-dev |
| MEDIUM | CVE-2024-56544 | kernel: udmabuf: change folios array from kmalloc to kvmalloc | linux-libc-dev |
| MEDIUM | CVE-2024-56549 | kernel: cachefiles: Fix NULL pointer dereference in object->file | linux-libc-dev |
| MEDIUM | CVE-2024-56565 | kernel: f2fs: fix to drop all discards after creating snapshot on lvm device | linux-libc-dev |
| MEDIUM | CVE-2024-56566 | kernel: mm/slub: Avoid list corruption when removing a slab from the full list | linux-libc-dev |
| MEDIUM | CVE-2024-56583 | kernel: sched/deadline: Fix warning in migrate_enable for boosted tasks | linux-libc-dev |
| MEDIUM | CVE-2024-56588 | kernel: scsi: hisi_sas: Create all dump files during debugfs initialization | linux-libc-dev |
| MEDIUM | CVE-2024-56591 | kernel: Bluetooth: hci_conn: Use disable_delayed_work_sync | linux-libc-dev |
| MEDIUM | CVE-2024-56592 | kernel: bpf: Call free_htab_elem() after htab_unlock_bucket() | linux-libc-dev |
| MEDIUM | CVE-2024-56599 | kernel: wifi: ath10k: avoid NULL pointer error during sdio remove | linux-libc-dev |
| MEDIUM | CVE-2024-56609 | kernel: wifi: rtw88: use ieee80211_purge_tx_queue() to purge TX skb | linux-libc-dev |
| MEDIUM | CVE-2024-56611 | kernel: mm/mempolicy: fix migrate_to_node() assuming there is at least one VMA in a MM | linux-libc-dev |
| MEDIUM | CVE-2024-56641 | kernel: net/smc: initialize close_work early to avoid warning | linux-libc-dev |
| MEDIUM | CVE-2024-56647 | kernel: net: Fix icmp host relookup triggering ip_rt_bug | linux-libc-dev |
| MEDIUM | CVE-2024-56657 | kernel: ALSA: control: Avoid WARN() for symlink errors | linux-libc-dev |
| MEDIUM | CVE-2024-56692 | kernel: f2fs: fix to do sanity check on node blkaddr in truncate_node() | linux-libc-dev |
| MEDIUM | CVE-2024-56703 | kernel: ipv6: Fix soft lockups in fib6_select_path under high next hop churn | linux-libc-dev |
| MEDIUM | CVE-2024-56712 | kernel: udmabuf: fix memory leak on last export_udmabuf() error path | linux-libc-dev |
| MEDIUM | CVE-2024-56719 | kernel: net: stmmac: fix TSO DMA API usage causing oops | linux-libc-dev |
| MEDIUM | CVE-2024-56729 | kernel: smb: Initialize cfid->tcon before performing network ops | linux-libc-dev |
| MEDIUM | CVE-2024-56742 | kernel: vfio/mlx5: Fix an unwind issue in mlx5vf_add_migration_pages() | linux-libc-dev |
| MEDIUM | CVE-2024-56757 | kernel: Bluetooth: btusb: mediatek: add intf release flow when usb disconnect | linux-libc-dev |
| MEDIUM | CVE-2024-56758 | kernel: btrfs: check folio mapping after unlock in relocate_one_folio() | linux-libc-dev |
| MEDIUM | CVE-2024-56782 | kernel: ACPI: x86: Add adev NULL check to acpi_quirk_skip_serdev_enumeration() | linux-libc-dev |
| MEDIUM | CVE-2024-56786 | kernel: bpf: put bpf_link's program when link is safe to be deallocated | linux-libc-dev |
| MEDIUM | CVE-2024-57795 | kernel: RDMA/rxe: Remove the direct link to net_device | linux-libc-dev |
| MEDIUM | CVE-2024-57802 | kernel: netrom: check buffer length before accessing it | linux-libc-dev |
| MEDIUM | CVE-2024-57804 | kernel: scsi: mpi3mr: Fix corrupt config pages PHY state is switched in sysfs | linux-libc-dev |
| MEDIUM | CVE-2024-57809 | kernel: PCI: imx6: Fix suspend/resume support on i.MX6QDL | linux-libc-dev |
| MEDIUM | CVE-2024-57841 | kernel: net: fix memory leak in tcp_conn_request() | linux-libc-dev |
| MEDIUM | CVE-2024-57843 | kernel: virtio-net: fix overflow inside virtnet_rq_alloc | linux-libc-dev |
| MEDIUM | CVE-2024-57857 | kernel: RDMA/siw: Remove direct link to net_device | linux-libc-dev |
| MEDIUM | CVE-2024-57872 | kernel: scsi: ufs: pltfrm: Dellocate HBA during ufshcd_pltfrm_remove() | linux-libc-dev |
| MEDIUM | CVE-2024-57875 | kernel: block: RCU protect disk->conv_zones_bitmap | linux-libc-dev |
| MEDIUM | CVE-2024-57882 | kernel: mptcp: fix TCP options overflow. | linux-libc-dev |
| MEDIUM | CVE-2024-57883 | kernel: mm: hugetlb: independent PMD page table shared count | linux-libc-dev |
| MEDIUM | CVE-2024-57884 | kernel: mm: vmscan: account for free pages to prevent infinite Loop in throttle_direct_reclaim() | linux-libc-dev |
| MEDIUM | CVE-2024-57888 | kernel: workqueue: Do not warn when cancelling WQ_MEM_RECLAIM work from !WQ_MEM_RECLAIM worker | linux-libc-dev |
| MEDIUM | CVE-2024-57889 | kernel: pinctrl: mcp23s08: Fix sleeping in atomic context due to regmap locking | linux-libc-dev |
| MEDIUM | CVE-2024-57890 | kernel: RDMA/uverbs: Prevent integer overflow issue | linux-libc-dev |
| MEDIUM | CVE-2024-57893 | kernel: ALSA: seq: oss: Fix races at processing SysEx messages | linux-libc-dev |
| MEDIUM | CVE-2024-57894 | kernel: Bluetooth: hci_core: Fix sleeping function called from invalid context | linux-libc-dev |
| MEDIUM | CVE-2024-57895 | kernel: ksmbd: set ATTR_CTIME flags when setting mtime | linux-libc-dev |
| MEDIUM | CVE-2024-57897 | kernel: drm/amdkfd: Correct the migration DMA map direction | linux-libc-dev |
| MEDIUM | CVE-2024-57898 | kernel: wifi: cfg80211: clear link ID from bitmap during link delete after clean up | linux-libc-dev |
| MEDIUM | CVE-2024-57899 | kernel: wifi: mac80211: fix mbss changed flags corruption on 32 bit systems | linux-libc-dev |
| MEDIUM | CVE-2024-57901 | kernel: af_packet: fix vlan_get_protocol_dgram() vs MSG_PEEK | linux-libc-dev |
| MEDIUM | CVE-2024-57902 | kernel: af_packet: fix vlan_get_tci() vs MSG_PEEK | linux-libc-dev |
| MEDIUM | CVE-2024-57903 | kernel: net: restrict SO_REUSEPORT to inet sockets | linux-libc-dev |
| MEDIUM | CVE-2024-57904 | kernel: iio: adc: at91: call input_free_device() on allocated iio_dev | linux-libc-dev |
| MEDIUM | CVE-2024-57906 | kernel: iio: adc: ti-ads8688: fix information leak in triggered buffer | linux-libc-dev |
| MEDIUM | CVE-2024-57907 | kernel: iio: adc: rockchip_saradc: fix information leak in triggered buffer | linux-libc-dev |
| MEDIUM | CVE-2024-57908 | kernel: iio: imu: kmx61: fix information leak in triggered buffer | linux-libc-dev |
| MEDIUM | CVE-2024-57912 | kernel: iio: pressure: zpa2326: fix information leak in triggered buffer | linux-libc-dev |
| MEDIUM | CVE-2024-57913 | kernel: usb: gadget: f_fs: Remove WARN_ON in functionfs_bind | linux-libc-dev |
| MEDIUM | CVE-2024-57915 | kernel: usb: gadget: u_serial: Disable ep before setting port to null to fix the crash caused by port being null | linux-libc-dev |
| MEDIUM | CVE-2024-57916 | kernel: misc: microchip: pci1xxxx: Resolve kernel panic during GPIO IRQ handling | linux-libc-dev |
| MEDIUM | CVE-2024-57917 | kernel: topology: Keep the cpumask unchanged when printing cpumap | linux-libc-dev |
| MEDIUM | CVE-2024-57922 | kernel: drm/amd/display: Add check for granularity in dml ceil/floor helpers | linux-libc-dev |
| MEDIUM | CVE-2024-57924 | kernel: fs: relax assertions on failure to encode file handles | linux-libc-dev |
| MEDIUM | CVE-2024-57925 | kernel: ksmbd: fix a missing return value check bug | linux-libc-dev |
| MEDIUM | CVE-2024-57929 | kernel: dm array: fix releasing a faulty array block twice in dm_array_cursor_end | linux-libc-dev |
| MEDIUM | CVE-2024-57930 | kernel: tracing: Have process_string() also allow arrays | linux-libc-dev |
| MEDIUM | CVE-2024-57931 | kernel: selinux: ignore unknown extended permissions | linux-libc-dev |
| MEDIUM | CVE-2024-57938 | kernel: net/sctp: Prevent autoclose integer overflow in sctp_association_init() | linux-libc-dev |
| MEDIUM | CVE-2024-57939 | kernel: riscv: Fix sleeping in invalid context in die() | linux-libc-dev |
| MEDIUM | CVE-2024-57940 | kernel: exfat: fix the infinite loop in exfat_readdir() | linux-libc-dev |
| MEDIUM | CVE-2024-57945 | kernel: riscv: mm: Fix the out of bound issue of vmemmap address | linux-libc-dev |
| MEDIUM | CVE-2024-57948 | kernel: mac802154: check local interfaces before deleting sdata list | linux-libc-dev |
| MEDIUM | CVE-2025-21629 | kernel: net: reenable NETIF_F_IPV6_CSUM offload for BIG TCP packets | linux-libc-dev |
| MEDIUM | CVE-2025-21634 | kernel: cgroup/cpuset: remove kernfs active break | linux-libc-dev |
| MEDIUM | CVE-2025-21635 | kernel: rds: sysctl: rds_tcp_{rcv,snd}buf: avoid using current->nsproxy | linux-libc-dev |
| MEDIUM | CVE-2025-21636 | kernel: sctp: sysctl: plpmtud_probe_interval: avoid using current->nsproxy | linux-libc-dev |
| MEDIUM | CVE-2025-21637 | In the Linux kernel, the following vulnerability has been resolved:  s ... | linux-libc-dev |
| MEDIUM | CVE-2025-21638 | kernel: sctp: sysctl: auth_enable: avoid using current->nsproxy | linux-libc-dev |
| MEDIUM | CVE-2025-21639 | kernel: sctp: sysctl: rto_min/max: avoid using current->nsproxy | linux-libc-dev |
| MEDIUM | CVE-2025-21640 | kernel: sctp: sysctl: cookie_hmac_alg: avoid using current->nsproxy | linux-libc-dev |
| MEDIUM | CVE-2025-21645 | kernel: platform/x86/amd/pmc: Only disable IRQ1 wakeup where i8042 actually enabled it | linux-libc-dev |
| MEDIUM | CVE-2025-21646 | kernel: afs: Fix the maximum cell name length | linux-libc-dev |
| MEDIUM | CVE-2025-21649 | kernel: net: hns3: fix kernel crash when 1588 is sent on HIP08 devices | linux-libc-dev |
| MEDIUM | CVE-2025-21651 | kernel: net: hns3: don't auto enable misc vector | linux-libc-dev |
| MEDIUM | CVE-2025-21653 | kernel: net_sched: cls_flow: validate TCA_FLOW_RSHIFT attribute | linux-libc-dev |
| MEDIUM | CVE-2025-21655 | kernel: io_uring/eventfd: ensure io_eventfd_signal() defers another RCU period | linux-libc-dev |
| MEDIUM | CVE-2025-21656 | kernel: hwmon: (drivetemp) Fix driver producing garbage data when SCSI errors occur | linux-libc-dev |
| MEDIUM | CVE-2025-21658 | kernel: btrfs: avoid NULL pointer dereference if no valid extent tree | linux-libc-dev |
| MEDIUM | CVE-2025-21660 | kernel: ksmbd: fix unexpectedly changed path in ksmbd_vfs_kern_path_locked | linux-libc-dev |
| MEDIUM | CVE-2025-21662 | kernel: net/mlx5: Fix variable not being completed when function returns | linux-libc-dev |
| MEDIUM | CVE-2025-21664 | kernel: dm thin: make get_first_thin use rcu-safe list first function | linux-libc-dev |
| MEDIUM | CVE-2025-21665 | kernel: filemap: avoid truncating 64-bit offset to 32 bits | linux-libc-dev |
| MEDIUM | CVE-2025-21666 | kernel: vsock: prevent null-ptr-deref in vsock_*[has_data|has_space] | linux-libc-dev |
| MEDIUM | CVE-2025-21667 | kernel: iomap: avoid avoid truncating 64-bit offset to 32 bits | linux-libc-dev |
| MEDIUM | CVE-2025-21668 | kernel: pmdomain: imx8mp-blk-ctrl: add missing loop break condition | linux-libc-dev |
| MEDIUM | CVE-2025-21669 | kernel: vsock/virtio: discard packets if the transport changes | linux-libc-dev |
| MEDIUM | CVE-2025-21672 | kernel: afs: Fix merge preference rule failure condition | linux-libc-dev |
| MEDIUM | CVE-2025-21673 | kernel: smb: client: fix double free of TCP_Server_Info::hostname | linux-libc-dev |
| MEDIUM | CVE-2025-21675 | kernel: net/mlx5: Clear port select structure when fail to create | linux-libc-dev |
| MEDIUM | CVE-2025-21676 | kernel: net: fec: handle page_pool_dev_alloc_pages error | linux-libc-dev |
| MEDIUM | CVE-2025-21678 | kernel: gtp: Destroy device along with udp socket's netns dismantle. | linux-libc-dev |
| MEDIUM | CVE-2025-21681 | kernel: openvswitch: fix lockup on tx to unregistering netdev with carrier | linux-libc-dev |
| MEDIUM | CVE-2025-21682 | kernel: eth: bnxt: always recalculate features after XDP clearing, fix null-deref | linux-libc-dev |
| MEDIUM | CVE-2025-21683 | kernel: bpf: Fix bpf_sk_select_reuseport() memory leak | linux-libc-dev |
| LOW | CVE-2004-0230 | TCP, when using a large Window Size, makes it easier for remote attack ... | linux-libc-dev |
| LOW | CVE-2005-3660 | Linux kernel 2.4 and 2.6 allows attackers to cause a denial of service ... | linux-libc-dev |
| LOW | CVE-2007-3719 | kernel: secretly Monopolizing the CPU Without Superuser Privileges | linux-libc-dev |
| LOW | CVE-2008-2544 | kernel: mounting proc readonly on a different mount point silently mounts it rw if the /proc mount is rw | linux-libc-dev |
| LOW | CVE-2008-4609 | kernel: TCP protocol vulnerabilities from Outpost24 | linux-libc-dev |
| LOW | CVE-2010-4563 | kernel: ipv6: sniffer detection | linux-libc-dev |
| LOW | CVE-2010-5321 | kernel: v4l: videobuf: hotfix a bug on multiple calls to mmap() | linux-libc-dev |
| LOW | CVE-2011-4915 | fs/proc/base.c in the Linux kernel through 3.1 allows local users to o ... | linux-libc-dev |
| LOW | CVE-2011-4916 | Linux kernel through 3.1 allows local users to obtain sensitive keystr ... | linux-libc-dev |
| LOW | CVE-2011-4917 | In the Linux kernel through 3.1 there is an information disclosure iss ... | linux-libc-dev |
| LOW | CVE-2012-4542 | kernel: block: default SCSI command filter does not accomodate commands overlap across device classes | linux-libc-dev |
| LOW | CVE-2014-9892 | The snd_compr_tstamp function in sound/core/compress_offload.c in the  ... | linux-libc-dev |
| LOW | CVE-2014-9900 | kernel: Info leak in uninitialized structure ethtool_wolinfo in ethtool_get_wol() | linux-libc-dev |
| LOW | CVE-2015-2877 | Kernel: Cross-VM ASL INtrospection (CAIN) | linux-libc-dev |
| LOW | CVE-2016-10723 | An issue was discovered in the Linux kernel through 4.17.2. Since the  ... | linux-libc-dev |
| LOW | CVE-2016-8660 | kernel: xfs: local DoS due to a page lock order bug in the XFS seek hole/data implementation | linux-libc-dev |
| LOW | CVE-2017-0630 | kernel: Information disclosure vulnerability in kernel trace subsystem | linux-libc-dev |
| LOW | CVE-2017-13693 | kernel: ACPI operand cache leak in dsutils.c | linux-libc-dev |
| LOW | CVE-2017-13694 | kernel: ACPI node and node_ext cache leak | linux-libc-dev |
| LOW | CVE-2018-1121 | procps: process hiding through race condition enumerating /proc | linux-libc-dev |
| LOW | CVE-2018-12928 | kernel: NULL pointer dereference in hfs_ext_read_extent in hfs.ko | linux-libc-dev |
| LOW | CVE-2018-17977 | kernel: Mishandled interactions among XFRM Netlink messages, IPPROTO_AH packets, and IPPROTO_IP packets resulting in a denial of service | linux-libc-dev |
| LOW | CVE-2019-11191 | kernel: race condition in load_aout_binary() allows local users to bypass ASLR on setuid a.out programs | linux-libc-dev |
| LOW | CVE-2019-12378 | kernel: unchecked kmalloc of new_ra in ip6_ra_control leads to denial of service | linux-libc-dev |
| LOW | CVE-2019-12379 | kernel: memory leak in con_insert_unipair in drivers/tty/vt/consolemap.c | linux-libc-dev |
| LOW | CVE-2019-12380 | kernel: memory allocation failure in the efi subsystem leads to denial of service | linux-libc-dev |
| LOW | CVE-2019-12381 | kernel: unchecked kmalloc of new_ra in ip_ra_control leads to denial of service | linux-libc-dev |
| LOW | CVE-2019-12382 | kernel: unchecked kstrdup of fwstr in drm_load_edid_firmware leads to denial of service | linux-libc-dev |
| LOW | CVE-2019-12455 | kernel: null pointer dereference in sunxi_divs_clk_setup in drivers/clk/sunxi/clk-sunxi.c causing denial of service | linux-libc-dev |
| LOW | CVE-2019-12456 | kernel: double fetch in the MPT3COMMAND case in _ctl_ioctl_main in drivers/scsi/mpt3sas/mpt3sas_ctl.c | linux-libc-dev |
| LOW | CVE-2019-16229 | kernel: null pointer dereference in drivers/gpu/drm/amd/amdkfd/kfd_interrupt.c | linux-libc-dev |
| LOW | CVE-2019-16230 | kernel: null pointer dereference in drivers/gpu/drm/radeon/radeon_display.c | linux-libc-dev |
| LOW | CVE-2019-16231 | kernel: null-pointer dereference in drivers/net/fjes/fjes_main.c | linux-libc-dev |
| LOW | CVE-2019-16232 | kernel: null-pointer dereference in drivers/net/wireless/marvell/libertas/if_sdio.c | linux-libc-dev |
| LOW | CVE-2019-16233 | kernel: null pointer dereference in drivers/scsi/qla2xxx/qla_os.c | linux-libc-dev |
| LOW | CVE-2019-16234 | kernel: null pointer dereference in drivers/net/wireless/intel/iwlwifi/pcie/trans.c | linux-libc-dev |
| LOW | CVE-2019-19070 | kernel: A memory leak in the spi_gpio_probe() function in drivers/spi/spi-gpio.c allows for a DoS | linux-libc-dev |
| LOW | CVE-2019-19378 | kernel: out-of-bounds write in index_rbio_pages in fs/btrfs/raid56.c | linux-libc-dev |
| LOW | CVE-2020-11725 | kernel: improper handling of private_size*count multiplication due to count=info->owner typo | linux-libc-dev |
| LOW | CVE-2020-35501 | kernel: audit not logging access to syscall open_by_handle_at for users with CAP_DAC_READ_SEARCH capability | linux-libc-dev |
| LOW | CVE-2021-26934 | An issue was discovered in the Linux kernel 4.18 through 5.10.16, as u ... | linux-libc-dev |
| LOW | CVE-2021-3714 | kernel: Remote Page Deduplication Attacks | linux-libc-dev |
| LOW | CVE-2022-0400 | kernel: Out of bounds read in the smc protocol stack | linux-libc-dev |
| LOW | CVE-2022-1247 | kernel: A race condition bug in rose_connect() | linux-libc-dev |
| LOW | CVE-2022-25265 | kernel: Executable Space Protection Bypass | linux-libc-dev |
| LOW | CVE-2022-2961 | kernel: race condition in rose_bind() | linux-libc-dev |
| LOW | CVE-2022-3238 | kernel: ntfs3 local privledge escalation if NTFS character set and remount and umount called simultaneously | linux-libc-dev |
| LOW | CVE-2022-41848 | kernel: Race condition between mgslpc_ioctl and mgslpc_detach | linux-libc-dev |
| LOW | CVE-2022-44032 | Kernel: Race between cmm_open() and cm4000_detach() result in UAF | linux-libc-dev |
| LOW | CVE-2022-44033 | Kernel: A race condition between cm4040_open() and reader_detach() may result in UAF | linux-libc-dev |
| LOW | CVE-2022-44034 | Kernel: A use-after-free due to race between scr24x_open()  and scr24x_remove() | linux-libc-dev |
| LOW | CVE-2022-4543 | kernel: KASLR Prefetch Bypass Breaks KPTI | linux-libc-dev |
| LOW | CVE-2022-45884 | kernel: use-after-free due to race condition occurring in dvb_register_device() | linux-libc-dev |
| LOW | CVE-2022-45885 | kernel: use-after-free due to race condition occurring in dvb_frontend.c | linux-libc-dev |
| LOW | CVE-2023-23039 | kernel: tty: vcc: race condition leading to use-after-free in vcc_open() | linux-libc-dev |
| LOW | CVE-2023-26242 | afu_mmio_region_get_by_offset in drivers/fpga/dfl-afu-region.c in the  ... | linux-libc-dev |
| LOW | CVE-2023-31081 | An issue was discovered in drivers/media/test-drivers/vidtv/vidtv_brid ... | linux-libc-dev |
| LOW | CVE-2023-31085 | kernel: divide-by-zero error in ctrl_cdev_ioctl when do_div happens and erasesize is 0 | linux-libc-dev |
| LOW | CVE-2023-3640 | Kernel: x86/mm: a per-cpu entry area leak was identified through the init_cea_offsets function when prefetchnta and prefetcht2 instructions being used for the per-cpu entry area mapping to the user space | linux-libc-dev |
| LOW | CVE-2023-39191 | kernel: eBPF: insufficient stack type checks in dynptr | linux-libc-dev |
| LOW | CVE-2023-4134 | kernel: cyttsp4_core: use-after-free in cyttsp4_watchdog_work() | linux-libc-dev |
| LOW | CVE-2024-0564 | kernel: max page sharing of Kernel Samepage Merging (KSM) may cause memory deduplication | linux-libc-dev |
| LOW | CVE-2024-40918 | kernel: parisc: Try to fix random segmentation faults in package builds | linux-libc-dev |
| LOW | CVE-2024-42155 | kernel: s390/pkey: Wipe copies of protected- and secure-keys | linux-libc-dev |
| LOW | CVE-2024-50057 | kernel: usb: typec: tipd: Free IRQ only if it was requested before | linux-libc-dev |
| LOW | CVE-2024-50211 | kernel: udf: refactor inode_bmap() to handle error | linux-libc-dev |
| LOW | TEMP-0000000-F7A20F | [Kernel: Unprivileged user can freeze journald] | linux-libc-dev |
| MEDIUM | CVE-2023-4641 | shadow-utils: possible password leak during passwd(1) change | login |
| LOW | CVE-2007-5686 | initscripts in rPath Linux 1 sets insecure permissions for the /var/lo ... | login |
| LOW | CVE-2023-29383 | shadow: Improper input validation in shadow-utils package utility chfn | login |
| LOW | CVE-2024-56433 | shadow-utils: Default subordinate ID configuration in /etc/login.defs could lead to compromise | login |
| LOW | TEMP-0628843-DBAD28 | [more related to CVE-2005-4890] | login |
| LOW | CVE-2008-1687 | m4: unquoted output of maketemp and mkstemp | m4 |
| LOW | CVE-2008-1688 | m4: code execution via -F argument | m4 |
| MEDIUM | CVE-2024-21096 | mysql: Client: mysqldump unspecified vulnerability (CPU Apr 2024) | mariadb-common |
| LOW | CVE-2022-0563 | util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline | mount |
| MEDIUM | CVE-2023-50495 | ncurses: segmentation fault via _nc_wrap_entry() | ncurses-base |
| MEDIUM | CVE-2023-50495 | ncurses: segmentation fault via _nc_wrap_entry() | ncurses-bin |
| LOW | CVE-2007-2243 | OpenSSH 4.6 and earlier, when ChallengeResponseAuthentication is enabl ... | openssh-client |
| LOW | CVE-2007-2768 | OpenSSH, when using OPIE (One-Time Passwords in Everything) for PAM, a ... | openssh-client |
| LOW | CVE-2008-3234 | sshd in OpenSSH 4 on Debian GNU/Linux, and the 20070303 OpenSSH snapsh ... | openssh-client |
| LOW | CVE-2016-20012 | openssh: Public key information leak | openssh-client |
| LOW | CVE-2018-15919 | openssh: User enumeration via malformed packets in authentication requests | openssh-client |
| LOW | CVE-2019-6110 | openssh: Acceptance and display of arbitrary stderr allows for spoofing of scp client output | openssh-client |
| LOW | CVE-2020-14145 | openssh: Observable discrepancy leading to an information leak in the algorithm negotiation | openssh-client |
| LOW | CVE-2020-15778 | openssh: scp allows command injection when using backtick characters in the destination argument | openssh-client |
| LOW | CVE-2023-51767 | openssh: authentication bypass via row hammer attack | openssh-client |
| MEDIUM | CVE-2024-13176 | openssl: Timing side-channel in ECDSA signature computation | openssl |
| MEDIUM | CVE-2023-4641 | shadow-utils: possible password leak during passwd(1) change | passwd |
| LOW | CVE-2007-5686 | initscripts in rPath Linux 1 sets insecure permissions for the /var/lo ... | passwd |
| LOW | CVE-2023-29383 | shadow: Improper input validation in shadow-utils package utility chfn | passwd |
| LOW | CVE-2024-56433 | shadow-utils: Default subordinate ID configuration in /etc/login.defs could lead to compromise | passwd |
| LOW | TEMP-0628843-DBAD28 | [more related to CVE-2005-4890] | passwd |
| LOW | CVE-2010-4651 | patch: directory traversal flaw allows for arbitrary file creation | patch |
| LOW | CVE-2018-6951 | patch: NULL pointer dereference in pch.c:intuit_diff_type() causes a crash | patch |
| LOW | CVE-2018-6952 | patch: Double free of memory in pch.c:another_hunk() causes a crash | patch |
| LOW | CVE-2021-45261 | patch: Invalid Pointer via another_hunk function | patch |
| HIGH | CVE-2023-31484 | perl: CPAN.pm does not verify TLS certificates when downloading distributions over HTTPS | perl |
| LOW | CVE-2011-4116 | perl: File:: Temp insecure temporary file handling | perl |
| LOW | CVE-2023-31486 | http-tiny: insecure TLS cert default | perl |
| HIGH | CVE-2023-31484 | perl: CPAN.pm does not verify TLS certificates when downloading distributions over HTTPS | perl-base |
| LOW | CVE-2011-4116 | perl: File:: Temp insecure temporary file handling | perl-base |
| LOW | CVE-2023-31486 | http-tiny: insecure TLS cert default | perl-base |
| HIGH | CVE-2023-31484 | perl: CPAN.pm does not verify TLS certificates when downloading distributions over HTTPS | perl-modules-5.36 |
| LOW | CVE-2011-4116 | perl: File:: Temp insecure temporary file handling | perl-modules-5.36 |
| LOW | CVE-2023-31486 | http-tiny: insecure TLS cert default | perl-modules-5.36 |
| LOW | CVE-2023-4016 | procps: ps buffer overflow | procps |
| MEDIUM | CVE-2025-0938 | python: cpython: URL parser allowed square brackets in domain names | python3.11 |
| MEDIUM | CVE-2025-0938 | python: cpython: URL parser allowed square brackets in domain names | python3.11-minimal |
| LOW | CVE-2024-46901 | Subversion: Apache Subversion: mod_dav_svn denial-of-service via control characters in paths | subversion |
| LOW | TEMP-0517018-A83CE6 | [sysvinit: no-root option in expert installer exposes locally exploitable security flaw] | sysvinit-utils |
| LOW | CVE-2005-2541 | tar: does not properly warn the user when extracting setuid or setgid files | tar |
| LOW | TEMP-0290435-0B57B5 | [tar's rmt command may have undesired side effects] | tar |
| LOW | CVE-2021-35331 | In Tcl 8.6.11, a format string vulnerability in nmakehlp.c might allow ... | tcl8.6 |
| LOW | CVE-2021-35331 | In Tcl 8.6.11, a format string vulnerability in nmakehlp.c might allow ... | tcl8.6-dev |
| LOW | CVE-2021-4217 | unzip: Null pointer dereference in Unicode strings code | unzip |
| LOW | CVE-2022-0563 | util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline | util-linux |
| LOW | CVE-2022-0563 | util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline | util-linux-extra |
| LOW | CVE-2022-0563 | util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline | uuid-dev |
| CRITICAL | CVE-2024-38428 | wget: Misinterpretation of input may lead to improper behavior | wget |
| MEDIUM | CVE-2021-31879 | wget: authorization header disclosure on redirect | wget |
| MEDIUM | CVE-2024-10524 | wget: GNU Wget is vulnerable to an SSRF attack when accessing partially-user-controlled shorthand URLs | wget |
| CRITICAL | CVE-2023-45853 | zlib: integer overflow and resultant heap-based buffer overflow in zipOpenNewFileInZip4_6 | zlib1g |
| CRITICAL | CVE-2023-45853 | zlib: integer overflow and resultant heap-based buffer overflow in zipOpenNewFileInZip4_6 | zlib1g-dev |
| HIGH | CVE-2024-6345 | pypa/setuptools: Remote code execution via download functions in the package_index module in pypa/setuptools | setuptools |

## Nota
Estas vulnerabilidades son generadas automáticamente mediante Trivy.
