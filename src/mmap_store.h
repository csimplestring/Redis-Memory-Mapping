/*
 * mmap_store.h
 *
 *  Created on: Dec 23, 2012
 *      Author: wangyi
 */

#ifndef MMAP_STORE_H_
#define MMAP_STORE_H_

void mmapMarkPageFree(off_t page);
void mmapMarkPagesFree(off_t page, off_t count);
void mmapMarkPageUsed(off_t page);
void mmapMarkPagesUsed(off_t page, off_t count);
off_t mmapSavedObjectPages(robj *o);
int mmapFreePage(off_t page);
int mmapFindContiguousPages(off_t *first, off_t n) ;

void mmapSeek(mmap_ptr *mp, off_t offset);
void mmapRewind(mmap_ptr *mp);

vmpointer *createMmapPointer(robj *o);

/*******************save object in mmap-file********************************/
int mmapWriteRaw(mmap_ptr *sp, void *p, size_t len);
int mmapSaveLen(mmap_ptr *sp, uint32_t len);
int mmapSaveDoubleValue(mmap_ptr *p, double val);
int mmapSaveLongLongAsStringObject(mmap_ptr *sp, long long value);
int mmapSaveLzfStringObject(mmap_ptr *sp, unsigned char *s, size_t len);
int mmapSaveRawString(mmap_ptr *sp, unsigned char *s, size_t len);
int mmapSaveStringObject(mmap_ptr *sp, robj *obj);
int mmapSaveObject(mmap_ptr *sp, robj *o);
int mmapWriteObjectOnSwap(robj *o, off_t page);
vmpointer *mmapSwapObjectBlocking(robj *val);

/****************load object from mmap-file**************************/
int mmapReadRaw(mmap_ptr *mp, void *dest, size_t len );
uint32_t mmapLoadLen(mmap_ptr *sp, int *isencoded) ;
int mmapLoadDoubleValue(mmap_ptr *sp, double *val);
robj *mmapLoadIntegerObject(mmap_ptr *sp, int enctype, int encode);
robj *mmapLoadLzfStringObject(mmap_ptr *sp);
robj *mmapGenericLoadStringObject(mmap_ptr *sp, int encode);
robj *mmapLoadObject(int type, mmap_ptr *sp);
robj *mmapReadObjectFromSwap(off_t page, int type);
robj *mmapReadObject(vmpointer *vp, int preview);

void mmapRemoveObject(redisDb *db, robj *key);



#endif /* MMAP_STORE_H_ */

