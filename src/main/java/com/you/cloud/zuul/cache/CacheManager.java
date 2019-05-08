package com.you.cloud.zuul.cache;

import cn.hutool.cache.CacheUtil;
import cn.hutool.cache.impl.TimedCache;


public class CacheManager {
    private static TimedCache<String, String> timedCache;

    private static TimedCache<String, String> getTimedCache(){
        if (timedCache == null){
            timedCache = CacheUtil.newTimedCache(1000*60*5);
            timedCache.schedulePrune(1000);
        }
        return timedCache;
    }

    public static String getValue(String key){
       return getTimedCache().get(key,false);
    }

    public static void setValue(String key,String value){
        getTimedCache().put(key,value);
    }
}
