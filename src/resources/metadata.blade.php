{{--GENERATED WITH https://www.samltool.com/idp_metadata.php--}}
{{--http://idp.[MYSITE] is just the Entity id, it doesn't need to exist, just needs to be unique--}}
{{--We have to escape the document definition as well or it doesn't run on certain php implementations --}}
<{{'?'}}xml version="1.0"{{'?'}}>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="2100-01-01T00:00:00Z" cacheDuration="PT1535772621S" entityID="{{config('saml.idp.entityId')}}">
    <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:KeyDescriptor use="signing">
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
                    <ds:X509Certificate>{{$certificate}}</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:KeyDescriptor use="encryption">
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
                    <ds:X509Certificate>{{$certificate}}</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </md:KeyDescriptor>
        <!-- If using HTTP-POST bindings you need to setup a new route to handle post based logins -->
        <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{{url('/postLogin')}}"/>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{{url('logout')}}"/>
    </md:IDPSSODescriptor>
</md:EntityDescriptor>