/* FSAL API
 * object oriented fsal api.
 */

/* fsal manager
 */

/* fsal object definition
 * base of fsal instance definition
 */

struct fsal_module {
	struct glist_head fsals;	/* list of loaded fsals */
	pthread_mutex_t lock;
	volatile int refs;
	struct glist_head exports;	/* list of exports from this fsal */
	char *name;			/* name set from .so and/or config */
	char *path;			/* path to .so file */
	void *dl_handle;		/* NULL if statically linked */
	struct fsal_ops *ops;
	fsal_functions_t *legacy_ops; /* compatibility layer */
	struct fsal_alloc_ops *alloc_ops; /* only legacy.c can use these */
};

/* fsal module methods */

struct fsal_export;

struct fsal_ops {
	/* base methods implemented in fsal_manager.c */
	int (*unload)(struct fsal_module *fsal_hdl);
	const char *(*get_name)(struct fsal_module *fsal_hdl);
	const char *(*get_lib_name)(struct fsal_module *fsal_hdl);
	int (*put)(struct fsal_module *fsal_hdl);
	/* subclass/instance methods in each fsal */
	fsal_status_t (*init_config)(struct fsal_module *fsal_hdl,
				     config_file_t config_struct);
	void (*dump_config)(struct fsal_module *fsal_hdl,
			    int log_fd);
	fsal_status_t (*create_export)(struct fsal_module *fsal_hdl,
				       const char *export_path,
				       const char *fs_options,
				       struct fsal_export **export);
};

/* global fsal manager functions
 * used by nfs_main to initialize fsal modules */

int start_fsals(config_file_t config);
int load_fsal(const char *path,
	      const char *name,
	      struct fsal_module **fsal_hdl);
int init_fsals(config_file_t config);

/* Called only within MODULE_INIT and MODULE_FINI functions
 * of a fsal module
 */

int register_fsal(struct fsal_module *fsal_hdl,
		  const char *name);
int unregister_fsal(struct fsal_module *fsal_hdl);

/* find and take a reference on a fsal
 * part of export setup.  Call the 'put' to release
 * your reference before unloading.
 */

struct fsal_module *lookup_fsal(const char *name);

/* export object
 * Created by fsal and referenced by the export list
 */

struct fsal_obj_handle;
struct exportlist__; /* we just need a pointer, not all of nfs_exports.h */

struct fsal_export {
	struct fsal_module *fsal;
	pthread_mutex_t lock;
	volatile int refs;
	struct glist_head handles;	/* list of obj handles still active */
	struct glist_head exports;
	struct exportlist__ *exp_entry; /* NYI points back to exp list */
	struct export_ops *ops;
};

struct fsal_obj_handle;

struct export_ops {
	/* export management */
	void (*get)(struct fsal_export *exp_hdl);
	void (*put)(struct fsal_export *exp_hdl);
	fsal_status_t (*release)(struct fsal_export *exp_hdl);

	/* create an object handle within this export */
	fsal_status_t (*lookup)(struct fsal_export *exp_hdl,
				struct fsal_obj_handle *parent,
				fsal_path_t *path,
				struct fsal_obj_handle **handle);
	fsal_status_t (*lookup_path)(struct fsal_export *exp_hdl,
				     fsal_path_t *path,
				     struct fsal_obj_handle **handle);
	fsal_status_t (*lookup_junction)(struct fsal_export *exp_hdl,
				struct fsal_obj_handle *junction,
				struct fsal_obj_handle **handle);
	fsal_status_t (*create_handle)(struct fsal_export *exp_hdl,
				       fsal_digesttype_t in_type,
				       caddr_t in_buff,
				       struct fsal_obj_handle **handle);

	/* statistics and configuration access */
	fsal_status_t (*get_fs_dynamic_info)(struct fsal_export *exp_hdl,
					     fsal_dynamicfsinfo_t *infop);
	fsal_boolean_t (*fs_supports)(struct fsal_export *exp_hdl,
					fsal_fsinfo_options_t option);
	fsal_size_t (*fs_maxfilesize)(struct fsal_export *exp_hdl);
	fsal_size_t (*fs_maxread)(struct fsal_export *exp_hdl);
	fsal_size_t (*fs_maxwrite)(struct fsal_export *exp_hdl);
	fsal_count_t (*fs_maxlink)(struct fsal_export *exp_hdl);
	fsal_mdsize_t (*fs_maxnamelen)(struct fsal_export *exp_hdl);
	fsal_mdsize_t (*fs_maxpathlen)(struct fsal_export *exp_hdl);
	fsal_fhexptype_t (*fs_fh_expire_type)(struct fsal_export *exp_hdl);
	fsal_time_t (*fs_lease_time)(struct fsal_export *exp_hdl);
	fsal_aclsupp_t (*fs_acl_support)(struct fsal_export *exp_hdl);
	fsal_attrib_mask_t (*fs_supported_attrs)(struct fsal_export *exp_hdl);
	fsal_accessmode_t (*fs_umask)(struct fsal_export *exp_hdl);
	fsal_accessmode_t (*fs_xattr_access_rights)(struct fsal_export *exp_hdl);

	/* quotas are managed at the file system (export) level */
	fsal_status_t (*get_quota)(struct fsal_export *exp_hdl,
				   fsal_path_t * pfsal_path,
				   int quota_type,
				   fsal_uid_t fsal_uid,
				   fsal_quota_t * pquota);
	fsal_status_t (*set_quota)(struct fsal_export *exp_hdl,
				   fsal_path_t * pfsal_path,
				   int quota_type,
				   fsal_uid_t fsal_uid,
				   fsal_quota_t * pquota,
				   fsal_quota_t * presquota);
};

/* filesystem object
 * used for files of all types including directories, anything
 * that has a usable handle.
 */

struct fsal_obj_handle {
	pthread_mutex_t lock;
	struct glist_head handles;
	int refs;
	fsal_nodetype_t type;
	struct fsal_export *export;	/* export who created me */
	fsal_attrib_list_t *attrs;  /* NYI  either decl or pointer */
	struct fsal_obj_ops *ops;
};

#if 0
/* test_* are candidates for removal
 * these functions move to the core and are called by the core
 * prior to calling the handle/file method.  If access is not allowed
 * the core *must not* call the fsal method.
 */
	fsal_status_t (*access)(struct fsal_obj_handle *obj_hdl, ...);
	fsal_status_t (*test_access)(struct fsal_obj_handle *obj_hdl, ...);
	fsal_status_t (*test_rename_access)(struct fsal_obj_handle *obj_hdl, ...);
	fsal_status_t (*test_unlink_access)(struct fsal_obj_handle *obj_hdl, ...);
	fsal_status_t (*test_create_access)(struct fsal_obj_handle *obj_hdl, ...);
	fsal_status_t (*test_link_access)(struct fsal_obj_handle *obj_hdl, ...);
	fsal_status_t (*test_setattr_access)(struct fsal_obj_handle *obj_hdl, ...);
#endif

/* NOTE: protos with '...)' are not implemented yet including what real
 * args will replace the ellipsis
 */

struct fsal_obj_ops {
	/* object handle reference management */
	void (*get)(struct fsal_obj_handle *obj_hdl);
	int (*put)(struct fsal_obj_handle *obj_hdl);

	/* create a file of some type with attributes in directory dir_hdl */
	fsal_status_t (*create)(struct fsal_obj_handle *dir_hdl,
				fsal_name_t *name,
				fsal_attrib_list_t *attrib,
				struct fsal_obj_handle **new_obj);
	fsal_status_t (*mkdir)(struct fsal_obj_handle *dir_hdl,
			       fsal_name_t *name,
			       fsal_attrib_list_t *attrib,
			       struct fsal_obj_handle **new_obj);
	fsal_status_t (*mknode)(struct fsal_obj_handle *dir_hdl,
				fsal_name_t *name,
				fsal_nodetype_t nodetype,  /* IN */
				fsal_dev_t *dev,  /* IN */
				fsal_attrib_list_t *attrib,
				struct fsal_obj_handle **new_obj);
	fsal_status_t (*symlink)(struct fsal_obj_handle *dir_hdl,
				 fsal_name_t *name,
				 fsal_path_t *link_path,
				 fsal_attrib_list_t *attrib,
				 struct fsal_obj_handle **new_obj);

	fsal_status_t (*getattrs)(struct fsal_obj_handle *obj_hdl,
				  fsal_attrib_list_t *obj_attr);
	fsal_status_t (*setattrs)(struct fsal_obj_handle *obj_hdl,
				  fsal_attrib_list_t *attrib_set);
	fsal_status_t (*getextattrs)(struct fsal_obj_handle *obj_hdl, ...);
	fsal_status_t (*link)(struct fsal_obj_handle *obj_hdl, ...);
	fsal_status_t (*opendir)(struct fsal_obj_handle *obj_hdl, ...);
	fsal_status_t (*open)(struct fsal_obj_handle *obj_hdl, ...);
	fsal_status_t (*open_by_name)(struct fsal_obj_handle *obj_hdl, ...);
	fsal_status_t (*open_by_fileid)(struct fsal_obj_handle *obj_hdl, ...);
	fsal_status_t (*readlink)(struct fsal_obj_handle *obj_hdl, ...);
	fsal_status_t (*rename)(struct fsal_obj_handle *obj_hdl, ...);
	fsal_status_t (*unlink)(struct fsal_obj_handle *obj_hdl, ...);
	fsal_status_t (*truncate)(struct fsal_obj_handle *obj_hdl, ...);
	fsal_status_t (*list_ext_attrs)(struct fsal_obj_handle *obj_hdl, ...);
	fsal_status_t (*getextattr_id_by_name)(struct fsal_obj_handle *obj_hdl, ...);
	fsal_status_t (*getextattr_value_by_name)(struct fsal_obj_handle *obj_hdl, ...);
	fsal_status_t (*getextattr_value_by_id)(struct fsal_obj_handle *obj_hdl, ...);
	fsal_status_t (*setextattr_value)(struct fsal_obj_handle *obj_hdl, ...);
	fsal_status_t (*setextattr_value_by_id)(struct fsal_obj_handle *obj_hdl, ...);
	fsal_status_t (*getextattr_attrs)(struct fsal_obj_handle *obj_hdl, ...);
	fsal_status_t (*remove_extattr_by_id)(struct fsal_obj_handle *obj_hdl, ...);
	fsal_status_t (*remove_extattr_by_name)(struct fsal_obj_handle *obj_hdl, ...);
	fsal_boolean_t (*handle_is)(struct fsal_obj_handle *obj_hdl,
				    fsal_nodetype_t type);
	fsal_boolean_t (*compare)(struct fsal_obj_handle *obj1_hdl,
				  struct fsal_obj_handle *obj2_hdl);
	unsigned int (*handle_to_hashidx)(struct fsal_obj_handle *obj_hdl,
					   unsigned int cookie,
					   unsigned int alphabet_len,
					   unsigned int index_size);
	unsigned int (*handle_to_rbtidx)(struct fsal_obj_handle *obj_hdl,
					  unsigned int cookie);
	fsal_status_t (*handle_digest)(struct fsal_obj_handle *obj_hdl,
				       fsal_digesttype_t output_type,
				       caddr_t out_buff);
	fsal_status_t (*release)(struct fsal_obj_handle *obj_hdl);
	fsal_status_t (*rcp)(struct fsal_obj_handle *obj_hdl, ...);
	fsal_status_t (*rcp_by_name)(struct fsal_obj_handle *obj_hdl, ...);
	fsal_status_t (*rcp_by_fileid)(struct fsal_obj_handle *obj_hdl, ...);
};
	
/* directory object.  Primarily for readdir processing
 * there is an open fd on the dir in the fsal private part...
 */

struct fsal_dirobj {
	struct fsal_obj_handle *dir;
	uint64_t cookie;  /* placeholding */
	struct fsal_dir_ops *ops;
};

struct fsal_dir_ops {
	fsal_status_t (*readdir)(struct fsal_dirobj *dirobj, ...);
	fsal_status_t (*closedir)(struct fsal_dirobj *dirobj, ...);
};

/* file object
 * implies an open fd.
 */

struct fsal_fileobj {
	struct fsal_obj_handle *objhdl;
	struct fsal_file_ops *ops;
};

struct fsal_file_ops {
	fsal_status_t (*read)(struct fsal_fileobj *file_hdl, ...);
	fsal_status_t (*write)(struct fsal_fileobj *file_hdl, ...);
	fsal_status_t (*sync)(struct fsal_fileobj *file_hdl, ...);
	fsal_status_t (*close)(struct fsal_fileobj *file_hdl, ...);
	fsal_status_t (*close_by_fileid)(struct fsal_fileobj *file_hdl, ...);
	fsal_status_t (*lock)(struct fsal_fileobj *file_hdl, ...); /* placeholder */
	fsal_status_t (*get_fileno)(struct fsal_fileobj *file_hdl, ...);
	fsal_status_t (*getattr)(struct fsal_fileobj *file_hdl,
				 fsal_attrib_list_t *obj_attr);
};

/* lock object.  really an open file...
 */
/* changelock, unlock, getlock deprecated.  new lock structure wip */
