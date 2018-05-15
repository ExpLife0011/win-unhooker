/**********************************************************************
* (c) Burluckij S.
* e-mail: burluckij@gmail.com
**********************************************************************/

/************************************************************************/
/* This file contains definitions of searching, sorting algorithms 		*/
/************************************************************************/

/* QSortFns sorts all functions from exported function by address from lowest to highest. */
EXTERN_C void QSortFns(PEXPORT_FN buf, int min_index, int max_index);

/* Finds index of a exported function bu its address in buf. */
EXTERN_C int LookupFn(PEXPORT_FN buf, int min_index, int max_index, PVOID pfn);