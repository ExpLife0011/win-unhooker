/**********************************************************************
* (c) Burluckij S.
* e-mail: burluckij@gmail.com
**********************************************************************/

#include "ntddk.h"
#include "ntdef.h"
#include "client0.h"
#include "w32.h"
#include "algo_t.h"

/* QSortFns sorts all functions from export section by addresses from lowest to highest. */
void QSortFns(PEXPORT_FN buf, int min_index, int max_index)
{
	PEXPORT_FN x = &buf[min_index + (max_index - min_index) / 2];
	int left = min_index;
	int right = max_index;

	while (left <= right)
	{
		/* слева на право: поиск элемента большего чем опорный */
		while (buf[left].addr < x->addr)
		{
			left++;
		}

		/* справа на лево: поиск элемента меньшего чем опорный */
		while (buf[right].addr > x->addr)
		{
			right--;
		}

		/* если индексы не пересеклись, значит обменять элементы */
		if (left <= right)
		{
			//swap(buf[left], buf[right]);
			EXPORT_FN temp;
			temp = buf[left];
			buf[left] = buf[right];
			buf[right] = temp;
			left++;
			right--;
		}
	}

	/* если есть что сортировать справа то сортируем */
	if (left < max_index)
		QSortFns(buf, left, max_index);

	/* сортируем оставшуюся  левую часть*/
	if (min_index < right)
		QSortFns(buf, min_index, right);
}

int LookupFn(PEXPORT_FN buf, int min_index, int max_index , PVOID pfn)
{
	int left = min_index, right = max_index, index = -1;

	while (left <= right)
	{
		index = left + (right - left) / 2;

		if ((ulong)pfn < (ulong)buf[index].addr)
		{
			right = index - 1;
		}
		else if ((ulong)pfn > (ulong)buf[index].addr) {
			left = index + 1;
		}
		else {
			return index;
		}
	}

	return -1;
}
