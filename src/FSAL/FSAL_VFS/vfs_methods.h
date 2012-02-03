/* VFS methods
 */

/*
 * VFS internal object handle
 * handle is a pointer because
 *  a) the last element of file_handle is a char[] meaning variable len...
 *  b) we cannot depend on it *always* being last or being the only
 *     variable sized struct here...  a pointer is safer.
 */

struct vfs_fsal_obj_handle {
	struct fsal_obj_handle obj_handle;
	struct file_handle *handle;
	int fd;
	fsal_openflags_t openflags;
};


	/* I/O management */
fsal_status_t vfs_open(struct fsal_obj_handle *obj_hdl,
		       fsal_openflags_t openflags);
fsal_status_t vfs_open_by_name(struct fsal_obj_handle *obj_hdl,
			       const char *filename,
			       fsal_openflags_t openflags);
fsal_status_t vfs_read(struct fsal_obj_handle *obj_hdl,
		       fsal_seek_t * seek_descriptor,
		       fsal_size_t buffer_size,
		       caddr_t buffer,
		       fsal_size_t * read_amount,
		       fsal_boolean_t * end_of_file); /* needed? */
fsal_status_t vfs_write(struct fsal_obj_handle *obj_hdl,
			fsal_seek_t * seek_descriptor,
			fsal_size_t buffer_size,
			caddr_t buffer,
			fsal_size_t * write_amount);
fsal_status_t vfs_commit(struct fsal_obj_handle *obj_hdl, /* sync */
			 off_t offset,
			 size_t len);
fsal_status_t vfs_lock_op(struct fsal_obj_handle *obj_hdl,
			  void * p_owner,
			  fsal_lock_op_t lock_op,
			  fsal_lock_param_t   request_lock,
			  fsal_lock_param_t * conflicting_lock);
fsal_status_t vfs_close(struct fsal_obj_handle *obj_hdl);
fsal_status_t vfs_rcp(struct fsal_obj_handle *obj_hdl,
		      const char *local_path,
		      fsal_rcpflag_t transfer_opt);
fsal_status_t vfs_rcp_by_name(struct fsal_obj_handle *obj_hdl,
			      const char *filename,
			      const char *local_path,
			      fsal_rcpflag_t transfer_opt);
