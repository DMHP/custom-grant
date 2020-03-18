/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.sample.identity.oauth2.grant.mobile;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.ResponseHeader;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;

/**
 * New grant type for Identity Server
 */
public class MobileGrant extends AbstractAuthorizationGrantHandler  {

    private static Log log = LogFactory.getLog(MobileGrant.class);


    public static final String MOBILE_GRANT_PARAM = "mobileNumber";

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext oAuthTokenReqMessageContext)  throws IdentityOAuth2Exception {

        log.info("Mobile Grant handler is hit");

        boolean authStatus = false;

        // extract request parameters
        RequestParameter[] parameters = oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getRequestParameters();

        String mobileNumber = null;

        // find out mobile number
        for(RequestParameter parameter : parameters){
            if(MOBILE_GRANT_PARAM.equals(parameter.getKey())){
                if(parameter.getValue() != null && parameter.getValue().length > 0){
                    mobileNumber = parameter.getValue()[0];
                }
            }
        }

        if(mobileNumber != null) {
            //validate mobile number
            authStatus =  isValidMobileNumber(mobileNumber);

            if(authStatus) {
                // if valid set authorized mobile number as grant user
                AuthenticatedUser mobileUser = new AuthenticatedUser();
                mobileUser.setUserName(mobileNumber);
                oAuthTokenReqMessageContext.setAuthorizedUser(mobileUser);
                oAuthTokenReqMessageContext.setScope(oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getScope());
            } else{
                ResponseHeader responseHeader = new ResponseHeader();
                responseHeader.setKey("SampleHeader-999");
                responseHeader.setValue("Provided Mobile Number is Invalid.");
                oAuthTokenReqMessageContext.addProperty("RESPONSE_HEADERS", new ResponseHeader[]{responseHeader});
            }

        }

        return authStatus;
    }

    /**
     * TODO
     *
     * You need to implement how to validate the mobile number
     *
     * @param mobileNumber
     * @return
     */
    private boolean isValidMobileNumber(String mobileNumber){

        // just demo validation

        if(mobileNumber.startsWith("033")){
            return true;
        }

        return false;
    }

}
