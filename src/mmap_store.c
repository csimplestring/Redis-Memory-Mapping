/*
 * mmap_store.c
 *
 *  Created on: Dec 23, 2012
 *      Author: wangyi
 */
#include "redis.h"
#include "mmap_store.h"

#include <math.h>
#include <sys/mman.h>
#include <fcntl.h>

/*
 * save object on mmap-file APIs
 */

/* Create a pointer pointing to value in mmaped-file */
vmpointer *createMmapPointer(robj *o) {
    vmpointer *vp = zmalloc(sizeof(vmpointer));
    vp->type = REDIS_VMPOINTER;
    vp->storage = REDIS_VM_SWAPPED;
    vp->vtype = getObjectSaveType(o);
    return vp;
}

/* Mark the page as free */
void mmapMarkPageFree(off_t page) {
    off_t byte = page/8;
    int bit = page&7;
    redisAssert(mmapFreePage(page) == 0);
    server.mmap_bitmap[byte] &= ~(1<<bit);
}

/* Mark N contiguous pages as free, with 'page' being the first. */
void mmapMarkPagesFree(off_t page, off_t count) {
    off_t j;

    for (j = 0; j < count; j++)
        mmapMarkPageFree(page+j);
    server.mmap_stats_used_pages -= count;
    redisLog(REDIS_DEBUG,"Mark FREE pages: %lld pages at %lld\n",
        (long long)count, (long long)page);
}

/* Mark the page as used */
void mmapMarkPageUsed(off_t page) {
    off_t byte = page/8;
    int bit = page&7;
    redisAssert(mmapFreePage(page) == 1);
    server.mmap_bitmap[byte] |= 1<<bit;
}

/* Mark N contiguous pages as used, with 'page' being the first. */
void mmapMarkPagesUsed(off_t page, off_t count) {
    off_t j;

    for (j = 0; j < count; j++)
        mmapMarkPageUsed(page+j);
    server.mmap_stats_used_pages += count;
    redisLog(REDIS_DEBUG,"Mark USED pages: %lld pages at %lld\n",
        (long long)count, (long long)page);
}

off_t mmapSavedObjectPages(robj *o) {
    off_t bytes = rdbSavedObjectLen(o);
    return (bytes+(server.mmap_page_size-1))/server.mmap_page_size;
}

/* Test if the page is free */
int mmapFreePage(off_t page) {
    off_t byte = page/8;
    int bit = page&7;
    return (server.mmap_bitmap[byte] & (1<<bit)) == 0;
}

int mmapFindContiguousPages(off_t *first, off_t n)
{
    off_t base, offset = 0, since_jump = 0, numfree = 0;

    if (server.mmap_near_pages == REDIS_VM_MAX_NEAR_PAGES) {
        server.mmap_near_pages = 0;
        server.mmap_next_page = 0;
    }
    server.mmap_near_pages++; /* Yet another try for pages near to the old ones */
    base = server.mmap_next_page;

    while(offset < server.mmap_pages) {
        off_t this = base+offset;

        /* If we overflow, restart from page zero */
        if (this >= server.mmap_pages) {
            this -= server.mmap_pages;
            if (this == 0) {
                /* Just overflowed, what we found on tail is no longer
                 * interesting, as it's no longer contiguous. */
                numfree = 0;
            }
        }
        if (mmapFreePage(this)) {
            /* This is a free page */
            numfree++;
            /* Already got N free pages? Return to the caller, with success */
            if (numfree == n) {
                *first = this-(n-1);
                server.mmap_next_page = this+1;
                redisLog(REDIS_DEBUG, "FOUND CONTIGUOUS PAGES: %lld pages at %lld\n", (long long) n, (long long) *first);
                return REDIS_OK;
            }
        } else {
            /* The current one is not a free page */
            numfree = 0;
        }

        /* Fast-forward if the current page is not free and we already
         * searched enough near this place. */
        since_jump++;
        if (!numfree && since_jump >= REDIS_VM_MAX_RANDOM_JUMP/4) {
            offset += random() % REDIS_VM_MAX_RANDOM_JUMP;
            since_jump = 0;
            /* Note that even if we rewind after the jump, we are don't need
             * to make sure numfree is set to zero as we only jump *if* it
             * is set to zero. */
        } else {
            /* Otherwise just check the next page */
            offset++;
        }
    }
    return REDIS_ERR;
}

void mmapSeek(mmap_ptr *mp, off_t offset)
{
	mp->current_ptr += offset;
}

void mmapRewind(mmap_ptr *mp)
{
	mp->current_ptr = mp->start_ptr;
}

int mmapWriteRaw(mmap_ptr *mp, void *p, size_t len)
{
	memcpy(mp->current_ptr, p, len);
	mmapSeek(mp, len);
	return len;
}

int mmapReadRaw(mmap_ptr *mp, void *dest, size_t len )
{
	memcpy(dest, mp->current_ptr, len);
	mmapSeek(mp, len);
	return len;
}

int mmapSaveLen(mmap_ptr *p, uint32_t len)
{
	unsigned char buf[2];
	    int nwritten;

	    if (len < (1<<6)) {
	        /* Save a 6 bit len */
	        buf[0] = (len&0xFF)|(REDIS_RDB_6BITLEN<<6);
	        if (mmapWriteRaw(p,buf,1) == -1) return -1;

	        nwritten = 1;
	    } else if (len < (1<<14)) {
	        /* Save a 14 bit len */
	        buf[0] = ((len>>8)&0xFF)|(REDIS_RDB_14BITLEN<<6);
	        buf[1] = len&0xFF;
	        if (mmapWriteRaw(p,buf,2) == -1) return -1;

	        nwritten = 2;
	    } else {
	        /* Save a 32 bit len */
	        buf[0] = (REDIS_RDB_32BITLEN<<6);
	        if (mmapWriteRaw(p,buf,1) == -1) return -1;
	        len = htonl(len);
	        if (mmapWriteRaw(p,&len,4) == -1) return -1;
	        nwritten = 1+4;
	    }
	    return nwritten;
}

int mmapSaveDoubleValue(mmap_ptr *p, double val) {
    unsigned char buf[128];
    int len;

    if (isnan(val)) {
        buf[0] = 253;
        len = 1;
    } else if (!isfinite(val)) {
        len = 1;
        buf[0] = (val < 0) ? 255 : 254;
    } else {
#if (DBL_MANT_DIG >= 52) && (LLONG_MAX == 0x7fffffffffffffffLL)
        /* Check if the float is in a safe range to be casted into a
         * long long. We are assuming that long long is 64 bit here.
         * Also we are assuming that there are no implementations around where
         * double has precision < 52 bit.
         *
         * Under this assumptions we test if a double is inside an interval
         * where casting to long long is safe. Then using two castings we
         * make sure the decimal part is zero. If all this is true we use
         * integer printing function that is much faster. */
        double min = -4503599627370495; /* (2^52)-1 */
        double max = 4503599627370496; /* -(2^52) */
        if (val > min && val < max && val == ((double)((long long)val)))
            ll2string((char*)buf+1,sizeof(buf),(long long)val);
        else
#endif
            snprintf((char*)buf+1,sizeof(buf)-1,"%.17g",val);
        buf[0] = strlen((char*)buf+1);
        len = buf[0]+1;
    }
    return mmapWriteRaw(p,buf,len);
}

int mmapSaveLongLongAsStringObject(mmap_ptr *sp, long long value)
{
	unsigned char buf[32];
	int n, nwritten = 0;
	int enclen = rdbEncodeInteger(value, buf);

	if (enclen > 0) {
		int ret = mmapWriteRaw(sp, buf, enclen);

		return ret;
	} else {
		/* Encode as string */
		enclen = ll2string((char*) buf, 32, value);
		redisAssert(enclen < 32);
		if ((n = mmapSaveLen(sp, enclen)) == -1)
			return -1;
		nwritten += n;
		if ((n = mmapWriteRaw(sp, buf, enclen)) == -1)
			return -1;

		nwritten += n;
	}
	return nwritten;
}

int mmapSaveLzfStringObject(mmap_ptr *sp, unsigned char *s, size_t len)
{
    size_t comprlen, outlen;
    unsigned char byte;
    int n, nwritten = 0;
    void *out;

    /* We require at least four bytes compression for this to be worth it */
    if (len <= 4) return 0;
    outlen = len-4;
    if ((out = zmalloc(outlen+1)) == NULL) return 0;
    comprlen = lzf_compress(s, len, out, outlen);
    if (comprlen == 0) {
        zfree(out);
        return 0;
    }

    byte = (REDIS_RDB_ENCVAL<<6)|REDIS_RDB_ENC_LZF;
    if ((n = mmapWriteRaw(sp,&byte,1)) == -1) goto writeerr;
    nwritten += n;

    if ((n = mmapSaveLen(sp,comprlen)) == -1) goto writeerr;
    nwritten += n;

    if ((n = mmapSaveLen(sp,len)) == -1) goto writeerr;
    nwritten += n;

    if ((n = mmapWriteRaw(sp,out,comprlen)) == -1) goto writeerr;
    nwritten += n;

    zfree(out);
    return nwritten;

writeerr:
    zfree(out);
    return -1;
}

int mmapSaveRawString(mmap_ptr *p, unsigned char *s, size_t len)
{
	int enclen;
	    int n, nwritten = 0;

	    /* Try integer encoding */
	    if (len <= 11) {
	        unsigned char buf[5];
	        if ((enclen = rdbTryIntegerEncoding((char*)s,len,buf)) > 0) {
	            if (mmapWriteRaw(p,buf,enclen) == -1) return -1;
	            return enclen;
	        }
	    }

	    /* Try LZF compression - under 20 bytes it's unable to compress even
	     * aaaaaaaaaaaaaaaaaa so skip it */
	    if (server.rdbcompression && len > 20) {
	        n = mmapSaveLzfStringObject(p,s,len);
	        if (n == -1) return -1;
	        if (n > 0) return n;
	        /* Return value of 0 means data can't be compressed, save the old way */
	    }

	    /* Store verbatim */
	    if ((n = mmapSaveLen(p,len)) == -1) return -1;
	    nwritten += n;
	    if (len > 0) {
	        if (mmapWriteRaw(p,s,len) == -1) return -1;
	        nwritten += len;
	    }
	    return nwritten;
}

int mmapSaveStringObject(mmap_ptr *p, robj *obj)
{
	if (obj->encoding == REDIS_ENCODING_INT) {
		return mmapSaveLongLongAsStringObject(p, (long) obj->ptr);
	} else {
		redisAssert(obj->encoding == REDIS_ENCODING_RAW);
		return mmapSaveRawString(p, obj->ptr, sdslen(obj->ptr));
	}
}

int mmapSaveObject(mmap_ptr *p, robj *o)
{
	int n, nwritten = 0;

	if (o->type == REDIS_STRING) {
		/* Save a string value */
		if ((n = mmapSaveStringObject(p,o)) == -1) return -1;
		nwritten += n;
	} else if (o->type == REDIS_HASH) {
        /* Save a hash value */
        if (o->encoding == REDIS_ENCODING_ZIPMAP) {
            size_t l = zipmapBlobLen((unsigned char*)o->ptr);

            if ((n = mmapSaveRawString(p,o->ptr,l)) == -1) return -1;
            nwritten += n;
        } else {
            dictIterator *di = dictGetIterator(o->ptr);
            dictEntry *de;

            if ((n = mmapSaveLen(p,dictSize((dict*)o->ptr))) == -1) return -1;
            nwritten += n;

            while((de = dictNext(di)) != NULL) {
                robj *key = dictGetEntryKey(de);
                robj *val = dictGetEntryVal(de);

                if ((n = mmapSaveStringObject(p,key)) == -1) return -1;
                nwritten += n;
                if ((n = mmapSaveStringObject(p,val)) == -1) return -1;
                nwritten += n;
            }
            dictReleaseIterator(di);
        }
    }else if (o->type == REDIS_ZSET) {
        /* Save a sorted set value */
        if (o->encoding == REDIS_ENCODING_ZIPLIST) {
            size_t l = ziplistBlobLen((unsigned char*)o->ptr);

            if ((n = mmapSaveRawString(p,o->ptr,l)) == -1) return -1;
            nwritten += n;
        } else if (o->encoding == REDIS_ENCODING_SKIPLIST) {
            zset *zs = o->ptr;
            dictIterator *di = dictGetIterator(zs->dict);
            dictEntry *de;

            if ((n = mmapSaveLen(p,dictSize(zs->dict))) == -1) return -1;
            nwritten += n;

            while((de = dictNext(di)) != NULL) {
                robj *eleobj = dictGetEntryKey(de);
                double *score = dictGetEntryVal(de);

                if ((n = mmapSaveStringObject(p,eleobj)) == -1) return -1;
                nwritten += n;
                if ((n = mmapSaveDoubleValue(p,*score)) == -1) return -1;
                nwritten += n;
            }
            dictReleaseIterator(di);
        } else {
            redisPanic("Unknown sorted set encoding");
        }
    }
	else {
	        redisPanic("Unknown object type");
	    }
	return nwritten;
}

int mmapWriteObjectOnSwap(robj *o, off_t page)
{
	// check offset reached the mmap size
	if(page >= server.mmap_poniter->mmap_file_size){
		 redisLog(REDIS_WARNING,
		            "Critical page has reached the end of the mmaped-file %s",
		            strerror(errno));
		        return REDIS_ERR;
	}

	mmap_ptr *sp = server.mmap_poniter;
	mmapRewind(sp);
	mmapSeek(sp, server.vm_page_size*page);
	mmapSaveObject(sp, o);

	return REDIS_OK;
}

vmpointer *mmapSwapObjectBlocking(robj *val)
{
	vmpointer *vp;
	off_t page;

	// 1 how many pages the 'value' is needed?
	off_t pages = mmapSavedObjectPages(val);

	// 2 find continuous pages for 'value'
	if (mmapFindContiguousPages(&page, pages) == REDIS_ERR) {
		return NULL;
	}

	// 3 write value in swap mmaped-file
	mmapWriteObjectOnSwap(val, page);

	// 4 switch to vm pointer
	vp = createMmapPointer(val);
	vp->page = page;	// page --> offset
	vp->usedpages = pages;	// usedpages --> length of value

	mmapMarkPagesUsed(page, pages);
	redisLog(REDIS_DEBUG, "VM: object %p swapped out at %lld (%lld pages)",
			(void*) val, (unsigned long long) page, (unsigned long long) pages);
	server.mmap_stats_swapped_objects++;
	server.mmap_stats_swapouts++;

	// 5 free value
	decrRefCount(val);

	return vp;
}

/*
 * laod object from mmap-file APIs
 */


uint32_t mmapLoadLen(mmap_ptr *mmp, int *isencoded) {
    unsigned char buf[2];
    uint32_t len;
    int type;

    if (isencoded) *isencoded = 0;
    mmapReadRaw(mmp, buf, 1);
    //mmapSeek(sp,1);
    type = (buf[0]&0xC0)>>6;
    if (type == REDIS_RDB_6BITLEN) {
        /* Read a 6 bit len */
        return buf[0]&0x3F;
    } else if (type == REDIS_RDB_ENCVAL) {
        /* Read a 6 bit len encoding type */
        if (isencoded) *isencoded = 1;
        return buf[0]&0x3F;
    } else if (type == REDIS_RDB_14BITLEN) {
        /* Read a 14 bit len */
        //if ( (buf[1]=sp[1]) == 0) return REDIS_RDB_LENERR;
    	mmapReadRaw(mmp, buf+1, 1);
    	//mmapSeek(sp,1);
    	return ((buf[0]&0x3F)<<8)|buf[1];
    } else {
        /* Read a 32 bit len */
    	sds len32 = sdsnewlen(mmp->current_ptr, 4);
    	//mmapSeek(sp,4);
    	len = atoi(len32);
    	sdsfree(len32);
        if ( len == 0) return REDIS_RDB_LENERR;
        return ntohl(len);
    }
}

robj *mmapLoadIntegerObject(mmap_ptr *sp, int enctype, int encode) {
    unsigned char enc[4];
    long long val;

    if (enctype == REDIS_RDB_ENC_INT8) {
        //if ((enc[0]=sp[0]) == 0) return NULL;

        mmapReadRaw(sp, enc, 1);
        //mmapSeek(sp,1);
        val = (signed char)enc[0];
    } else if (enctype == REDIS_RDB_ENC_INT16) {
        uint16_t v;
        mmapReadRaw(sp, enc, 2);
        //mmapSeek(sp,2);
        //if (fread(enc,2,1,fp) == 0) return NULL;
        v = enc[0]|(enc[1]<<8);
        val = (int16_t)v;
    } else if (enctype == REDIS_RDB_ENC_INT32) {
        uint32_t v;
        mmapReadRaw(sp, enc, 4);
        //mmapSeek(sp,4);
        //if (fread(enc,4,1,fp) == 0) return NULL;
        v = enc[0]|(enc[1]<<8)|(enc[2]<<16)|(enc[3]<<24);
        val = (int32_t)v;
    } else {
        val = 0; /* anti-warning */
        redisPanic("Unknown RDB integer encoding type");
    }
    if (encode)
        return createStringObjectFromLongLong(val);
    else
        return createObject(REDIS_STRING,sdsfromlonglong(val));
}

int mmapLoadDoubleValue(mmap_ptr *sp, double *val) {
    char buf[128];
    unsigned char len;

    if(mmapReadRaw(sp, &len, 1) == 0) return -1;
    //if (fread(&len,1,1,fp) == 0) return -1;
    switch(len) {
    case 255: *val = R_NegInf; return 0;
    case 254: *val = R_PosInf; return 0;
    case 253: *val = R_Nan; return 0;
    default:
    	if(mmapReadRaw(sp, buf, len) == 0) return -1;
        //if (fread(buf,len,1,fp) == 0) return -1;
        buf[len] = '\0';
        sscanf(buf, "%lg", val);
        return 0;
    }
}

robj *mmapLoadLzfStringObject(mmap_ptr *sp) {
    unsigned int len, clen;
    unsigned char *c = NULL;
    sds val = NULL;

    if ((clen = mmapLoadLen(sp,NULL)) == REDIS_RDB_LENERR) return NULL;
    if ((len = mmapLoadLen(sp,NULL)) == REDIS_RDB_LENERR) return NULL;
    if ((c = zmalloc(clen)) == NULL) goto err;
    if ((val = sdsnewlen(NULL,len)) == NULL) goto err;
    //if (fread(c,clen,1,fp) == 0) goto err;
    mmapReadRaw(sp, c, clen);
    //mmapSeek(sp,clen);
    if (lzf_decompress(c,clen,val,len) == 0) goto err;
    zfree(c);
    return createObject(REDIS_STRING,val);

    err:
    zfree(c);
    sdsfree(val);
    return NULL;
}

robj *mmapGenericLoadStringObject(mmap_ptr *sp, int encode) {
    int isencoded;
    uint32_t len;
    sds val;

    len = mmapLoadLen(sp,&isencoded);
    if (isencoded) {
        switch(len) {
        case REDIS_RDB_ENC_INT8:
        case REDIS_RDB_ENC_INT16:
        case REDIS_RDB_ENC_INT32:
            return mmapLoadIntegerObject(sp,len,encode);
        case REDIS_RDB_ENC_LZF:
            return mmapLoadLzfStringObject(sp);
        default:
            redisPanic("Unknown RDB encoding type");
        }
    }

    if (len == REDIS_RDB_LENERR) return NULL;
    val = sdsnewlen(NULL,len);
   if (len) {
       // memcpy(val, sp, len);
        //mmapSeek(sp,len);
	   mmapReadRaw(sp, val, len);
    }
    return createObject(REDIS_STRING,val);
}

robj *mmapLoadEncodedStringObject(mmap_ptr *sp) {
    return mmapGenericLoadStringObject(sp,1);
}

robj *mmapLoadStringObject(mmap_ptr *sp) {
    return mmapGenericLoadStringObject(sp,0);
}

robj *mmapLoadObject(int type, mmap_ptr *sp) {
    robj *o, *ele, *dec;
    size_t len;
    unsigned int i;

    if (type == REDIS_STRING) {
        /* Read string value */
        if ((o = mmapGenericLoadStringObject(sp,1)) == NULL) return NULL;
        o = tryObjectEncoding(o);
    }
    else if (type == REDIS_HASH) {
        size_t hashlen;

        if ((hashlen = mmapLoadLen(sp,NULL)) == REDIS_RDB_LENERR) return NULL;
        o = createHashObject();
        /* Too many entries? Use an hash table. */
        if (hashlen > server.hash_max_zipmap_entries)
            convertToRealHash(o);
        /* Load every key/value, then set it into the zipmap or hash
         * table, as needed. */
        while(hashlen--) {
            robj *key, *val;

            if ((key = mmapLoadEncodedStringObject(sp)) == NULL) return NULL;
            if ((val = mmapLoadEncodedStringObject(sp)) == NULL) return NULL;
            /* If we are using a zipmap and there are too big values
             * the object is converted to real hash table encoding. */
            if (o->encoding != REDIS_ENCODING_HT &&
               ((key->encoding == REDIS_ENCODING_RAW &&
                sdslen(key->ptr) > server.hash_max_zipmap_value) ||
                (val->encoding == REDIS_ENCODING_RAW &&
                sdslen(val->ptr) > server.hash_max_zipmap_value)))
            {
                    convertToRealHash(o);
            }

            if (o->encoding == REDIS_ENCODING_ZIPMAP) {
                unsigned char *zm = o->ptr;
                robj *deckey, *decval;

                /* We need raw string objects to add them to the zipmap */
                deckey = getDecodedObject(key);
                decval = getDecodedObject(val);
                zm = zipmapSet(zm,deckey->ptr,sdslen(deckey->ptr),
                                  decval->ptr,sdslen(decval->ptr),NULL);
                o->ptr = zm;
                decrRefCount(deckey);
                decrRefCount(decval);
                decrRefCount(key);
                decrRefCount(val);
            } else {
                key = tryObjectEncoding(key);
                val = tryObjectEncoding(val);
                dictAdd((dict*)o->ptr,key,val);
            }
        }
    }
    else if (type == REDIS_ZSET) {
            /* Read list/set value */
            size_t zsetlen;
            size_t maxelelen = 0;
            zset *zs;

            if ((zsetlen = mmapLoadLen(sp,NULL)) == REDIS_RDB_LENERR) return NULL;
            o = createZsetObject();
            zs = o->ptr;

            /* Load every single element of the list/set */
            while(zsetlen--) {
                robj *ele;
                double score;
                zskiplistNode *znode;

                if ((ele = mmapLoadEncodedStringObject(sp)) == NULL) return NULL;
                ele = tryObjectEncoding(ele);
                if (mmapLoadDoubleValue(sp,&score) == -1) return NULL;

                /* Don't care about integer-encoded strings. */
                if (ele->encoding == REDIS_ENCODING_RAW &&
                    sdslen(ele->ptr) > maxelelen)
                        maxelelen = sdslen(ele->ptr);

                znode = zslInsert(zs->zsl,score,ele);
                dictAdd(zs->dict,ele,&znode->score);
                incrRefCount(ele); /* added to skiplist */
            }

            /* Convert *after* loading, since sorted sets are not stored ordered. */
            if (zsetLength(o) <= server.zset_max_ziplist_entries &&
                maxelelen <= server.zset_max_ziplist_value)
                    zsetConvert(o,REDIS_ENCODING_ZIPLIST);
        }
    else if (type == REDIS_HASH_ZIPMAP ||
                   type == REDIS_LIST_ZIPLIST ||
                   type == REDIS_SET_INTSET ||
                   type == REDIS_ZSET_ZIPLIST)
        {
            robj *aux = mmapLoadStringObject(sp);

            if (aux == NULL) return NULL;
            o = createObject(REDIS_STRING,NULL); /* string is just placeholder */
            o->ptr = zmalloc(sdslen(aux->ptr));
            memcpy(o->ptr,aux->ptr,sdslen(aux->ptr));
            decrRefCount(aux);

            /* Fix the object encoding, and make sure to convert the encoded
             * data type into the base type if accordingly to the current
             * configuration there are too many elements in the encoded data
             * type. Note that we only check the length and not max element
             * size as this is an O(N) scan. Eventually everything will get
             * converted. */
            switch(type) {
                case REDIS_HASH_ZIPMAP:
                    o->type = REDIS_HASH;
                    o->encoding = REDIS_ENCODING_ZIPMAP;
                    if (zipmapLen(o->ptr) > server.hash_max_zipmap_entries)
                        convertToRealHash(o);
                    break;
                case REDIS_LIST_ZIPLIST:
                    o->type = REDIS_LIST;
                    o->encoding = REDIS_ENCODING_ZIPLIST;
                    if (ziplistLen(o->ptr) > server.list_max_ziplist_entries)
                        listTypeConvert(o,REDIS_ENCODING_LINKEDLIST);
                    break;
                case REDIS_SET_INTSET:
                    o->type = REDIS_SET;
                    o->encoding = REDIS_ENCODING_INTSET;
                    if (intsetLen(o->ptr) > server.set_max_intset_entries)
                        setTypeConvert(o,REDIS_ENCODING_HT);
                    break;
                case REDIS_ZSET_ZIPLIST:
                    o->type = REDIS_ZSET;
                    o->encoding = REDIS_ENCODING_ZIPLIST;
                    if (zsetLength(o) > server.zset_max_ziplist_entries)
                        zsetConvert(o,REDIS_ENCODING_SKIPLIST);
                    break;
                default:
                    redisPanic("Unknown encoding");
                    break;
            }
        }
    else {
        redisPanic("Unknown object type");
    }
    return o;
}

robj *mmapReadObjectFromSwap(off_t page, int type) {
    robj *o;

    mmap_ptr *mmp = server.mmap_poniter;
    mmapRewind(mmp);
    mmapSeek(mmp, server.vm_page_size*page);

    o = mmapLoadObject(type,mmp);
    if (o == NULL) {
        redisLog(REDIS_WARNING, "Unrecoverable VM problem in vmReadObjectFromSwap(): can't load object from swap file: %s", strerror(errno));
        _exit(1);
    }

    return o;
}

robj *mmapReadObject(vmpointer *vp, int preview)
{
    robj *val;

    val = mmapReadObjectFromSwap(vp->page,vp->vtype);
    if (!preview) {
        redisLog(REDIS_DEBUG, "VM: object %p loaded from disk", (void*)vp);
        mmapMarkPagesFree(vp->page,vp->usedpages);
        zfree(vp);
        server.mmap_stats_swapped_objects--;
    } else {
        redisLog(REDIS_DEBUG, "VM: object %p previewed from disk", (void*)vp);
    }
    server.mmap_stats_swapins++;
    return val;
}

void mmapRemoveObject(redisDb *db, robj *key)
{
	 dictEntry *de = dictFind(db->dict,key->ptr);
	    if (de) {
	        robj *val = dictGetEntryVal(de);
	        vmpointer *vp = (vmpointer*)val;
	        mmapMarkPagesFree(vp->page,vp->usedpages);
	        server.mmap_stats_swapped_objects--;
	    }
}
