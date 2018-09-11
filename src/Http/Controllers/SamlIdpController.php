<?php

namespace Pkeogan\LaravelSaml\Http\Controllers;

use Illuminate\Routing\Controller as Controller;
use Storage;
use Pkeogan\LaravelSaml\Http\Traits\SamlAuth;
use Illuminate\Http\Request;
use App\Events\Frontend\Auth\UserLoggedOut;
use App\Helpers\Auth\AuthHelper;
use Illuminate\Support\Facades\Auth;



class SamlIdpController extends Controller 
{
    use SamlAuth;

    protected function metadata() 
	{
        return response(
            $this->getSamlFile(config('saml.idp.metadata'), false),
            200, [
                'Content-Type' => 'application/xml'
            ]
        );
    }
	public function post(Request $request) 
	{
		dd( $request->session()->all() );
        return view('saml::post');
    }
	
	public function logoutAll(Request $request)
	{
		$user = Auth::user();
		if(!Auth::check())
		{ 
			return redirect('/login'); 
		}

		  app()->make(AuthHelper::class)->flushTempSession();
        /*
         * Fire event, Log out user, Redirect
         */
        event(new UserLoggedOut($user));

        /*
         * Laravel specific logic
         */
        $this->guard()->logout();
        $request->session()->invalidate();
		return view('saml::logout');
	}
	
	public function logout(Request $request)
	{
		$user = Auth::user();
		if(!Auth::check())
		{ 
			return redirect('/login'); 
		}

		  app()->make(AuthHelper::class)->flushTempSession();
        /*
         * Fire event, Log out user, Redirect
         */
        event(new UserLoggedOut($user));

        /*
         * Laravel specific logic
         */
        $this->guard()->logout();
        $request->session()->invalidate();
		return redirect()->route('frontend.auth.login')->with('samlLogout', true)->withFlashSuccess("You have been logged out of the system, and any applications on this web browser.");

		
	}
	    /**
     * Get the guard to be used during authentication.
     *
     * @return \Illuminate\Contracts\Auth\StatefulGuard
     */
    protected function guard()
    {
        return Auth::guard();
    }

}