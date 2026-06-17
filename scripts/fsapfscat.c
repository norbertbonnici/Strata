/*
 * fsapfscat — extract a single file's bytes from an APFS volume in a raw image.
 *
 * The Sleuth Kit's APFS parser crashes on real macOS volumes, and libyal's
 * fsapfsinfo lists/times files but cannot dump their content. This tiny tool
 * wraps the libfsapfs C API (the same calls fsapfstools/info_handle.c uses) to
 * read one file's data stream and write it to stdout — the macOS-image
 * equivalent of TSK's `icat`.
 *
 *   fsapfscat -o <byte offset> -f <0-based volume index>
 *             [-p <password>] [-r <recovery password>]
 *             [-x <extended attribute name>] <raw_image> <volume_path>
 *
 * With -x, the named extended attribute's bytes are written to stdout instead of
 * the file's data stream (used to recover the `com.apple.metadata:kMDItemWhereFroms`
 * download-provenance xattr). Exit code 3 means the attribute is not present.
 *
 * Built statically against the vendored libfsapfs by scripts/build-tsk.sh.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

/* libbfio is bundled inside libfsapfs.a but its public aggregator header isn't
 * installed. A minimal stub `libbfio.h` (just `typedef intptr_t
 * libbfio_handle_t;`) on the include path satisfies the BFIO-gated open
 * prototype that LIBFSAPFS_HAVE_BFIO exposes; build-tsk.sh generates that stub. */
#define LIBFSAPFS_HAVE_BFIO 1
#include <libfsapfs.h>

/* The four libbfio functions we call (C linkage matches by symbol name; the
 * width types come from libfsapfs.h above). */
extern int libbfio_file_range_initialize(libbfio_handle_t **handle, libfsapfs_error_t **error);
extern int libbfio_file_range_set_name(libbfio_handle_t *handle, const char *name, size_t name_length, libfsapfs_error_t **error);
extern int libbfio_file_range_set(libbfio_handle_t *handle, off64_t range_offset, size64_t range_size, libfsapfs_error_t **error);
extern int libbfio_handle_free(libbfio_handle_t **handle, libfsapfs_error_t **error);

static void fail(const char *msg, libfsapfs_error_t *error)
{
	fprintf(stderr, "fsapfscat: %s\n", msg);
	if (error != NULL) {
		libfsapfs_error_fprint(error, stderr);
		libfsapfs_error_free(&error);
	}
	exit(1);
}

int main(int argc, char *argv[])
{
	libfsapfs_error_t *error            = NULL;
	libbfio_handle_t *file_io_handle    = NULL;
	libfsapfs_container_t *container     = NULL;
	libfsapfs_volume_t *volume           = NULL;
	libfsapfs_file_entry_t *file_entry   = NULL;

	int64_t offset      = 0;
	int volume_index    = 0;
	const char *password = NULL;
	const char *recovery = NULL;
	const char *xattr_name = NULL;
	int option;

	while ((option = getopt(argc, argv, "o:f:p:r:x:")) != -1) {
		switch (option) {
			case 'o': offset       = strtoll(optarg, NULL, 10); break;
			case 'f': volume_index = (int) strtol(optarg, NULL, 10); break;
			case 'p': password     = optarg; break;
			case 'r': recovery     = optarg; break;
			case 'x': xattr_name   = optarg; break;
			default:
				fprintf(stderr, "Usage: fsapfscat -o offset -f index [-p pw] [-r rk] [-x attr] image path\n");
				return 1;
		}
	}
	if (argc - optind != 2) {
		fprintf(stderr, "Usage: fsapfscat -o offset -f index [-p pw] [-r rk] [-x attr] image path\n");
		return 1;
	}
	const char *image_path  = argv[optind];
	const char *volume_path = argv[optind + 1];

	/* Open the raw image as a byte-range starting at the APFS container offset. */
	if (libbfio_file_range_initialize(&file_io_handle, &error) != 1)
		fail("unable to initialize file IO handle", error);
	if (libbfio_file_range_set_name(file_io_handle, image_path, strlen(image_path), &error) != 1)
		fail("unable to set image name", error);
	if (libbfio_file_range_set(file_io_handle, (off64_t) offset, 0, &error) != 1)
		fail("unable to set container offset", error);

	if (libfsapfs_container_initialize(&container, &error) != 1)
		fail("unable to initialize container", error);
	if (libfsapfs_container_open_file_io_handle(container, file_io_handle, LIBFSAPFS_OPEN_READ, &error) != 1)
		fail("unable to open APFS container", error);

	if (libfsapfs_container_get_volume_by_index(container, volume_index, &volume, &error) != 1)
		fail("unable to get volume by index", error);

	/* FileVault: set the key, then unlock, before resolving paths. */
	if (password != NULL) {
		if (libfsapfs_volume_set_utf8_password(volume, (const uint8_t *) password, strlen(password), &error) != 1)
			fail("unable to set password", error);
	}
	if (recovery != NULL) {
		if (libfsapfs_volume_set_utf8_recovery_password(volume, (const uint8_t *) recovery, strlen(recovery), &error) != 1)
			fail("unable to set recovery password", error);
	}
	if (password != NULL || recovery != NULL) {
		if (libfsapfs_volume_unlock(volume, &error) != 1)
			fail("unable to unlock volume (bad password?)", error);
	}

	int result = libfsapfs_volume_get_file_entry_by_utf8_path(
	    volume, (const uint8_t *) volume_path, strlen(volume_path), &file_entry, &error);
	if (result == 0) {
		fprintf(stderr, "fsapfscat: no such file: %s\n", volume_path);
		return 2;
	}
	if (result != 1)
		fail("unable to resolve file path", error);

	uint8_t buffer[65536];

	if (xattr_name != NULL) {
		/* Dump the named extended attribute's bytes instead of the file data.
		 * get_by_utf8_name returns 0 when the attribute isn't present. */
		libfsapfs_extended_attribute_t *xattr = NULL;
		int xr = libfsapfs_file_entry_get_extended_attribute_by_utf8_name(
		    file_entry, (const uint8_t *) xattr_name, strlen(xattr_name), &xattr, &error);
		if (xr == 0) {
			libfsapfs_file_entry_free(&file_entry, NULL);
			libfsapfs_volume_free(&volume, NULL);
			libfsapfs_container_free(&container, NULL);
			libbfio_handle_free(&file_io_handle, NULL);
			return 3;   /* attribute not present */
		}
		if (xr != 1)
			fail("unable to get extended attribute", error);

		size64_t xattr_size = 0;
		if (libfsapfs_extended_attribute_get_size(xattr, &xattr_size, &error) != 1)
			fail("unable to get attribute size", error);

		size64_t remaining = xattr_size;
		while (remaining > 0) {
			size_t want = (remaining < sizeof(buffer)) ? (size_t) remaining : sizeof(buffer);
			ssize_t got = libfsapfs_extended_attribute_read_buffer(xattr, buffer, want, &error);
			if (got < 0)
				fail("attribute read error", error);
			if (got == 0)
				break;
			if (fwrite(buffer, 1, (size_t) got, stdout) != (size_t) got)
				fail("write error", NULL);
			remaining -= (size64_t) got;
		}
		libfsapfs_extended_attribute_free(&xattr, NULL);
	} else {
		size64_t file_size = 0;
		if (libfsapfs_file_entry_get_size(file_entry, &file_size, &error) != 1)
			fail("unable to get file size", error);

		size64_t remaining = file_size;
		while (remaining > 0) {
			size_t want = (remaining < sizeof(buffer)) ? (size_t) remaining : sizeof(buffer);
			ssize_t got = libfsapfs_file_entry_read_buffer(file_entry, buffer, want, &error);
			if (got < 0)
				fail("read error", error);
			if (got == 0)
				break;
			if (fwrite(buffer, 1, (size_t) got, stdout) != (size_t) got)
				fail("write error", NULL);
			remaining -= (size64_t) got;
		}
	}

	libfsapfs_file_entry_free(&file_entry, NULL);
	libfsapfs_volume_free(&volume, NULL);
	libfsapfs_container_free(&container, NULL);
	libbfio_handle_free(&file_io_handle, NULL);
	return 0;
}
