# Laravel SAML

Laravel-SAML implements a SAML2 IDP plugin to transform laravel into a SAML identity provider (IDP) beside the regular authentication. The package is designed to work with Laravel 5.4 or above.

The package is based on [Dustin Parham's guide to implement a SAML IDP with laravel](https://imbringingsyntaxback.com/implementing-a-saml-idp-with-laravel/). To get a better basic understanding for SAML in general, read [Cheung's SAML for Web Developers](https://github.com/jch/saml).

## Installation

### Basic package installation

Using ```composer```: 

``` 
composer require "kingstarter/laravel-saml":"dev-master"
```

#### Lightsaml dependency problem

In case you run in a current lightsaml dependency problem regarding symfony 4 (event dispatcher) you might consider [using a fork of lightsaml allowing to use symfony 4](https://github.com/kingstarter/laravel-saml/issues/8#issuecomment-366991715).

#### Laravel 5.4
Add the service provider to ```config/app.php```

```
    KingStarter\LaravelSaml\LaravelSamlServiceProvider::class,
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

#### Setting the entity id

In config/saml.php set the field idp.entity-id to your entity id. This is normally a uri, the uri doesn't need to exist, it just needs to be unique

    'idp' => [
        .....
        'entityId' => 'http://idp.wherever.com'
    ],
    
#### Generating metadata and certificates

There is a sample metadata template in storage/saml/idp/metadata.blade.php, This was generated using https://www.samltool.com/idp_metadata.php

Edit this template to customize it for your site.

When you're finished run the following command to generate certificates and the metadata file 

```
php artisan laravel-saml:generate-meta --cert
```

To use exisiting certificates just make sure they're present in the saml drive then run the command without the --cert option

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

    use SamlAuthenticatesUsers; 

.....
```


To allow later direct redirection when somebody is already logged in, we need to add also some lines to ```app/Http/Middleware/RedirectIfAuthenticated.php```:
```
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Support\Facades\Auth;

use KingStarter\LaravelSaml\Http\Traits\SamlAuth;

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
    public function handle($request, Closure $next, $guard = null)
    {
        if(Auth::check() && isset($request['SAMLRequest'])){  
            $this->handleSamlLoginRequest($request);
        }
        if (Auth::guard($guard)->check()) {
            return redirect('/home');
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
        '/postLogin'
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
