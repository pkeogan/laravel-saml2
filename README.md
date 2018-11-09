# Larvael + SAML2 Goodness

This repo was orginaly a fork of kingstarter/laravel-saml. It has since grown from that, and is now gives any laravel applcation the following abilites:
1 - Become a IDP
2 - Generate certs for signing messages, signing assertions and encryppting attributes. These certs use data inputed from the config file
3 - Configure attributes to be sent (From Config File)
4 - Configure for each SP if the message and/or assertion should be signed
5 - Provides the ability on the logout page to logout of any of the service provides via iframe

This package makes it so easy to matinin and a IDP. Docs need a little work, if your willing to help let me know.

## Installation

### Basic package installation

Using ```composer```: 

``` 
composer require "pkeogan/laravel-saml2":"dev-master"
```

#### Laravel 5.4
Add the service provider to ```config/app.php```

```
    Pkeogan\LaravelSaml\LaravelSamlServiceProvider::class,
```
#### Laravel 5.5+
This package supports Laravel's Package Auto Discovery and should be automatically loaded when required using composer. If the package is not auto discovered run

```bash
    php artisan package:discover
```
#### Configuration
There is one configuration file to publish and the config/filesystem.php file that needs to be extended. The command
```
php artisan vendor:publish --tag="saml_config"
```

will publish the config/saml.php file. 


#### FileSystem configuration 

Within ```config/filesystem.php``` following entry needs to be added:
```
    'disks' => [

        ...
        
        'saml' => [
            'driver' => 'local',
            'root' => storage_path().'/saml',
        ],

    ],
```

#### Fill out the config file 
 WIP 
    
#### Generating metadata and certificates

Once the config is filled out correcly, run the command below to generate the metadata and the cert. Please note, if no certs are located the system will generate them. If you would like to overide the certs, please use the ``--cert`` flag

```
php artisan laravel-saml:generate-meta
```

#### SAML SP entries

Within the saml.php config file the SAML Service Provider array needs to be filled. 

```
    'sp' => [

        //Tableau
        'https://sso.online.tableau.com/public/sp/SSO?alias=xxxx-xxxx-xxxx-xxxx-xxxxxxxx' => [
            'entity-id' => 'https://sso.online.tableau.com/public/sp/metadata?alias=xxxx-xxxx-xxxx-xxxx-xxxxxxxx',
            'certificate' => 'MIICozC........dUvTnGP18g=='
        ],

        //A nifty testing service provider
        'https://sptest.iamshowcase.com/acs' => [

        ]

    ],
```

### Using the SAML package

To use the SAML package, some files need to be modified. 
Within your login view, problably ```resources/views/auth/login.blade.php``` add a SAMLRequest field beneath the CSRF field 
(this is actually a good place for it):
```
    {{-- The hidden CSRF field for secure authentication --}}
    {{ csrf_field() }}
    {{-- Add a hidden SAML Request field for SAML authentication --}}
 	@if(isset($_GET['SAMLRequest']))
        <input type="hidden" id="SAMLRequest" name="SAMLRequest" value="{{ $_GET['SAMLRequest'] }}">
    @elseif(isset($saml))
        <input type="hidden" id="SAMLRequest" name="SAMLRequest" value="{{ $saml }}">
    @endif
    @if( config('saml.logout_apps_via_iframe') && session('samlLogout') ) 
	  	@include('saml::logout')
  	@endif
```

The SAMLRequest field will be filled automatically when a SAMLRequest is sent by a http request and therefore initiate a SAML authentication attempt.
 To initiate the SAML auth, the login and redirect functions need to be modified. 
 Within ```app/Http/Controllers/Auth/LoginController.php``` change ```use AuthenticatesUsers``` to ```use SamlAuthenticatesUsers```
 
```
use App\Http\Controllers\Controller;
use KingStarter\LaravelSaml\Http\Traits\SamlAuthenticatesUsers;

class LoginController extends Controller
{
...

      /**
     * The user has been authenticated.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  mixed  $user
     * @return mixed
     */
    protected function authenticated(Request $request, $user)
    {
        if(Auth::check() && isset($request['SAMLRequest'])) {
            $this->handleSamlLoginRequest($request);
        }

        return redirect()->intended($this->redirectPath());
    }

.....
```


To allow later direct redirection when somebody is already logged in, we need to add also some lines to ```app/Http/Middleware/RedirectIfAuthenticated.php```:
```
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Session;
use Pkeogan\LaravelSaml\Http\Traits\SamlAuth;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

class RedirectIfAuthenticated
{
        use SamlAuth;

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string|null  $guard
     * @return mixed
     */
    public function handle(Request $request, Closure $next, $guard = null)
    {
		if(Auth::check() && isset($request['SAMLRequest'])){
            $saml = $this->handleSamlLoginRequest($request);
			return new Response(view('saml::post')->withSaml($saml));
        } 
		
        if(Auth::guard($guard)->check() && !isset($request['SAMLRequest']) ) {
            return redirect('/');
        }
        return $next($request);
    }
}
```


### bindings:HTTP-POST 

If you're using HTTP post bindings then you'll need to allow saml to get the login request via post.

in web.php add the new route

```
....
Auth::routes();
Route::post('/postLogin', 'Auth\LoginController@showLoginForm');
```

You'll also need to add a csrf exemption to ```App\Http\Middleware\VerifyCsrfToken```

class VerifyCsrfToken extends Middleware
{
    /**
     * The URIs that should be excluded from CSRF verification.
     *
     * @var array
     */
    protected $except = [
       'login/saml', 'logout/saml'
    ];
}

### Debugging Connection

You can enable logging with the config/saml.php setting debug_saml_request

```
    // Allow debugging within SamlAuth trait to get SP data  
    // during SAML authentication request
    'debug_saml_request' => true,
```

Make sure that the environmental logging variable ```APP_LOG_LEVEL``` is set to debug within your ```.env``` file. It will log to ```storage/logs/laravel.log```
