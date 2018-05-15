

EXTERN_C plist_t __stdcall list_create();

/* Provides pointer to last object in list. */
EXTERN_C plist_t __stdcall list_tail(plist_t l);

EXTERN_C void __stdcall list_erase(plist_t list);

EXTERN_C ulong __stdcall list_length(const plist_t list);

EXTERN_C BOOLEAN __stdcall list_insert(plist_t list, PVOID object);

EXTERN_C void __stdcall list_to_buffer(plist_t plst, PVOID pBuffer, ulong size_of_type);