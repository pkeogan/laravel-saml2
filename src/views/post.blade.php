<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="SAML Post Page">
    <meta name="author" content="Peter Keogan">
    <title>SAML Post</title>
	<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.1.3/css/bootstrap.min.css" integrity="sha256-eSi1q2PG6J7g7ib17yAaWMcrr5GrtohYChqibrV7PBE=" crossorigin="anonymous" />
	<style>
	html,
	body {
		height: 100%;
	}
		
	.footer-text {
		font-size: 12px;
		color: #cdcdcd;
	}

	body {
		display: -ms-flexbox;
		display: -webkit-box;
		display: flex;
		-ms-flex-align: center;
		-ms-flex-pack: center;
		-webkit-box-align: center;
		align-items: center;
		-webkit-box-pack: center;
		justify-content: center;
		padding-top: 40px;
		padding-bottom: 40px;
		background-color: #f5f5f5;
	}

	.form-signin {
		width: 100%;
		max-width: 330px;
		padding: 15px;
		margin: 0 auto;
	}

	.form-signin .checkbox {
		font-weight: 400;
	}

	.form-signin .form-control {
		position: relative;
		box-sizing: border-box;
		height: auto;
		padding: 10px;
		font-size: 16px;
	}

	.form-signin .form-control:focus {
		z-index: 2;
	}

	.form-signin input[type="email"] {
		margin-bottom: -1px;
		border-bottom-right-radius: 0;
		border-bottom-left-radius: 0;
	}

	.form-signin input[type="password"] {
		margin-bottom: 10px;
		border-top-left-radius: 0;
		border-top-right-radius: 0;
	}
	</style>
  </head>
  <body @if(config('saml.post.auto', true))onload="document.form.submit()"@endif class="text-center">
    <form method="POST" name="form" action="{{ base64_decode($saml['recipient']) }}" accept-charset="UTF-8" class="form-signin">
		<h1>Logging into {{ $saml['name'] }}</h1>
		@if(config('saml.post.auto', true))
		<div class="alert alert-info" role="alert">
		  {{ config('saml.post.message', 'Your browser be automatically logging you in just a moment. If you are not redirected, please click the button below.') }}
		</div>
		@else
		<div class="alert alert-info" role="alert">
			Please click the button below to proceed.
		</div>
		@endif
		<input type="hidden" name="SAMLResponse" value="{{ $saml['response'] }}" /> 
		@if(isset($saml['relayState']))
		<input type="hidden" name="RelayState" value="{{ $saml['relayState'] }}" />
		@endif
      <button class="btn btn-lg btn-primary btn-block" type="submit">Proceed</button>
		</br>
	 	 {!! config('saml.post.footer') !!}
    </form>
  </body>
</html>