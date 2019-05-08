package com.you.cloud.zuul.filter;

import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.symmetric.SymmetricCrypto;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.you.cloud.zuul.cache.CacheManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.Iterator;

/**
 * @author shicz
 */
@Component
public class AuthFilter extends ZuulFilter {
    @Override
    public String filterType() {
        return "pre";
    }

    @Override
    public int filterOrder() {
        return 0;
    }

    @Override
    public boolean shouldFilter() {
        return true;
    }

    public void sendErrorResponse(RequestContext ctx, String body){
        ctx.addZuulResponseHeader("Content-Type","application/json; charset=UTF-8");
        ctx.setSendZuulResponse(false);
        ctx.setResponseBody(body);
        ctx.set("isSuccess", false);
    }  
    
    public void sendSuccessResponse(RequestContext ctx){
        ctx.setSendZuulResponse(true);
        ctx.set("isSuccess", true);
    }

    @Override
    public Object run() {
        RequestContext ctx = RequestContext.getCurrentContext();
        HttpServletRequest request = ctx.getRequest();
        String token = request.getHeader("token");
        String random = request.getHeader("random");
        String timestamp = request.getHeader("timestamp");
        String sign = request.getHeader("sign");
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("success",false);
        if (StrUtil.isEmpty(random)){
            jsonObject.put("code",1);
            jsonObject.put("message","header param random is empty.");
            sendErrorResponse(ctx,jsonObject.toString());
            return null;
        }else if (random.length() !=32){
            jsonObject.put("code",2);
            jsonObject.put("message","header param random is error.");
            sendErrorResponse(ctx,jsonObject.toString());
            return null;
        }
        if (StrUtil.isEmpty(timestamp)){
            jsonObject.put("code",1);
            jsonObject.put("message","header param timestamp is empty.");
            sendErrorResponse(ctx,jsonObject.toString());
            return null;
        }else if (timestamp.length() !=13){
            jsonObject.put("code",2);
            jsonObject.put("message","header param timestamp is error.");
            sendErrorResponse(ctx,jsonObject.toString());
            return null;
        }else {
            Long clientTime = 0L;
            try {
                clientTime = Long.parseLong(timestamp);
            }catch (Exception e){
                jsonObject.put("code",2);
                jsonObject.put("message","header param timestamp is error.");
                sendErrorResponse(ctx,jsonObject.toString());
                return null;
            }
            if ((System.currentTimeMillis() - clientTime)/1000 > 300){
                jsonObject.put("code",2);
                jsonObject.put("message","client clock and server clock deviation is too large.");
                sendErrorResponse(ctx,jsonObject.toString());
                return null;
            }
        }
        if (StrUtil.isEmpty(sign)){
            jsonObject.put("code",1);
            jsonObject.put("message","header param sign is empty.");
            sendErrorResponse(ctx,jsonObject.toString());
            return null;
        } else {
            String data = random.substring(0,16)+timestamp+random.substring(16)+token;
            String newSign = SecureUtil.md5(data);
            if (sign.equals(newSign)){
                if (CacheManager.getValue(sign) != null){
                    jsonObject.put("code",2);
                    jsonObject.put("message","header param sign is already used it.");
                    sendErrorResponse(ctx,jsonObject.toString());
                    return null;
                } else {
                    CacheManager.setValue(sign,token);
                }
            }else {
                jsonObject.put("code",2);
                jsonObject.put("message","header param sign is error.");
                sendErrorResponse(ctx,jsonObject.toString());
                return null;
            }
        }
        if (StrUtil.isNotEmpty(token)){
            try{
                SymmetricCrypto sm4 = new SymmetricCrypto("SM4");
                JSONObject json = JSONUtil.parseObj(sm4.decryptStr(token));
                if (json.size() == 0){
                    jsonObject.put("code",2);
                    jsonObject.put("message","header param token is error.");
                    sendErrorResponse(ctx,jsonObject.toString());
                    return null;
                }
                Iterator<String> iterator = json.keySet().iterator();
                while (iterator.hasNext()){
                    String key = iterator.next();
                    String value = json.getStr(key);
                    ctx.addZuulRequestHeader(key,value);
                }
                sendSuccessResponse(ctx);
                return null;
            }catch (Exception e){
                jsonObject.put("code",2);
                jsonObject.put("message","header param token is error.");
                sendErrorResponse(ctx,jsonObject.toString());
                return null;
            }
        }
        return null;
    }
}
