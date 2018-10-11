package com.sacem.custom.keyvalidator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.keymgt.APIKeyMgtException;
import org.wso2.carbon.apimgt.keymgt.handlers.DefaultKeyValidationHandler;
import org.wso2.carbon.apimgt.keymgt.service.TokenValidationContext;

public class KeyValidator extends DefaultKeyValidationHandler {

    private static final Log log = LogFactory.getLog(KeyValidator.class);

    @Override
    public boolean validateToken(TokenValidationContext tokenValidationContext)  {
        if(tokenValidationContext!=null){
            if(tokenValidationContext.getAccessToken()!=null) {
                /*As the WSO2 token length is 36, the check is done for that. If the token length is 36, invoke the
                usual super path, if not invoke the custom path */
                if (tokenValidationContext.getAccessToken().length()==36) {
                    System.out.println("=====================invoking default super token validator=================");
                    try {
                        return super.validateToken(tokenValidationContext);
                    } catch (APIKeyMgtException e) {
                    }
                } else {
                    System.out.println("=====================invoking custom token validator================");
                }
            }
        }

        return true;
    }

    @Override
    public boolean validateScopes(TokenValidationContext tokenValidationContext) throws APIKeyMgtException {
        log.info("=============================================");
        log.info("in validateScopes accesstoken = " + tokenValidationContext.getAccessToken());
        log.info("=============================================");
        log.info("Done");
        return true;
    }

    @Override
    public boolean validateSubscription(TokenValidationContext tokenValidationContext) throws APIKeyMgtException {
        super.validateSubscription(tokenValidationContext);
        log.info("=============================================");
        log.info("in validateSubscription accesstoken = " + tokenValidationContext.getAccessToken());
        log.info("=============================================");
        log.info("Done");
        return true;
    }

    @Override
    public boolean generateConsumerToken(TokenValidationContext tokenValidationContext) throws APIKeyMgtException {
        log.info("=============================================");
        log.info("in generateConsumerToken accesstoken = " + tokenValidationContext.getAccessToken());
        log.info("=============================================");
        return true;
    }
}
