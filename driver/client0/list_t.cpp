#include "ntddk.h"
#include "ntdef.h"
#include "client0.h"

#include "list_t.h"

plist_t list_tail(plist_t l)
{
	plist_t tail = NULL;

	if (tail = l){
		while(tail->pNext)
		{
			tail = (plist_t)tail->pNext;
		}
	}

	return tail;
}

plist_t list_create()
{
	plist_t plist = (plist_t)PAGE_MEM(sizeof(list_t));

	if (plist)
	{
		memset(plist, 0, sizeof(list_t));
	}

	return plist;
}

BOOLEAN list_insert(plist_t list, PVOID object)
{
	plist_t newentry = NULL;

	if (!list)
	{
		return FALSE;
	}

	list_t* tail = list_tail(list);

	// The list is empty
	if ((tail->pdata == NULL) && (tail->pNext == NULL))
	{
		newentry = tail;
	}
	else
	{
		// The list is nod empty, insert new item to the last position
		newentry = list_create();

		if (!newentry){
			return FALSE;
		}

		tail->pNext = newentry;
	}

	newentry->pdata = object;
	newentry->pNext = NULL;
	return TRUE;
}

// Destroys list_t object therefore list should be a dynamic object,
// allocated not in the stack
void list_erase(plist_t list)
{
	if (!list){
		return;
	}

	for (plist_t entry = list/*->pNext*/; entry;)
	{
		if (entry->pdata)
		{
			ExFreePool(entry->pdata);
			entry->pdata = NULL;
		}

		plist_t tmp = entry;
		entry = (plist_t)entry->pNext;

		ExFreePool(tmp);
	}
}

ulong list_length(const plist_t list)
{
	ulong length = 0;
	plist_t entry = list;

	while (entry)
	{
		entry = (plist_t)entry->pNext;
		++length;
	}

	return length;
}

// Fills output buffer
void list_to_buffer(plist_t plst, PVOID pBuffer, ulong size_of_type)
{
	for (plist_t lst_item = plst; lst_item; lst_item = (plist_t)lst_item->pNext)
	{
		memcpy(pBuffer, lst_item->pdata, size_of_type);
		pBuffer = (PUCHAR)pBuffer + size_of_type;
	}
}