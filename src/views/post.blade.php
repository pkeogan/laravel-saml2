
<!DOCTYPE html>
<html>

<head>
  <meta charset="utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="csrf-token" content="obJGAQZXYFUUqA3J4o8SwV04tHylIEVyyDcAzFuJ">
  <meta name="description" content="Applcation Made By Peter Keogan">
  <meta name="author" content="Peter Keogan">
  <meta content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no" name="viewport">
   <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png?v=pgqRLGNB2R">
<link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png?v=pgqRLGNB2R">
<link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png?v=pgqRLGNB2R">
<link rel="manifest" href="/site.webmanifest?v=pgqRLGNB2R">
<link rel="mask-icon" href="/safari-pinned-tab.svg?v=pgqRLGNB2R" color="#4e342e">
<link rel="shortcut icon" href="/favicon.ico?v=pgqRLGNB2R">
<meta name="msapplication-TileColor" content="#4e342e">
<meta name="msapplication-TileImage" content="/mstile-144x144.png?v=pgqRLGNB2R">
<meta name="theme-color" content="#4e342e">  
      <title>Hennepin EMS | SAML Auto Login</title>
      <!-- Import Styles -->
  <link media="all" type="text/css" rel="stylesheet" href="https://hennepinems.org/css/style.css">


  <!-- HTML5 Shim and Respond.js IE8 support of HTML5 elements and media queries -->
  <!-- WARNING: Respond.js doesn't work if you view the page via file:// -->
  <!--[if lt IE 9]>
  <script src="https://oss.maxcdn.com/html5shiv/3.7.3/html5shiv.min.js"></script>
  <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
  <![endif]-->

  <!-- Google Font -->
  <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Source+Sans+Pro:300,400,600,700,300italic,400italic,600italic"> 
  <link rel="stylesheet" href="https://pro.fontawesome.com/releases/v5.1.1/css/all.css" integrity="sha384-xyMU7RufUdPGVOZRrc2z2nRWVWBONzqa0NFctWglHmt5q5ukL22+lvHAqhqsIm3h" crossorigin="anonymous">

	<style>
	body {
	background: linear-gradient(
      rgba(0, 0, 0, 0.45), 
      rgba(0, 0, 0, 0.45)
    ), url('https://hennepinems.org/images/login-bg.jpg') no-repeat center center fixed !important;
    -webkit-background-size: cover !important;
    -moz-background-size: cover !important;
    -o-background-size: cover !important;
    background-size: cover !important;
		background-color: #000;
		color: #fff !important;
}
		.login-logo-light {
			color: #fff !important;
		}
	</style>
</head>
<!-- ADD THE CLASS layout-top-nav TO REMOVE THE SIDEBAR. -->

<body onload="document.form.submit()" class="hold-transition login-page">

  <div class="login-box">
  <div class="login-logo">
	  <img src="https://hennepinems.org/images/hems-patch-login.png" class="center-block" alt="HEMS Patch">

    <a href="https://hennepinems.org" class="login-logo-light"><b>Hennepin</b> EMS</a>
  </div>
  <!-- /.login-logo -->
    	   	    

  <div class="login-box-body">
    <p class="login-box-msg"> Since your browser does not support JavaScript, you must
            press the button below once to proceed.</p>
    <form method="POST" name="form" action="{{ base64_decode($saml['recipient']) }}" accept-charset="UTF-8" class="form-horizontal">
 	            <input type="hidden" name="SAMLResponse" value="{{ $saml['response'] }}" />
 	            @if(isset($saml['relayState']))<input type="hidden" name="RelayState" value="{{ $saml['relayState'] }}" />@endif
                    <div class="row form-group">
                     <div class="col-sm-12">
						 	<input class="btn btn-block btn-primary" type="submit" value="Proceed">
                        </div><!--col-md-10-->
	 				 </div>

      </form>

      </div>
  <!-- /.login-box-body -->
  </br>
      <p class="login-box-msg"> PLASMA <a class="login-logo-light" href="https://hennepinems.org">Verison 0.1A </a></p>
</div>
<!-- /.login-box -->
    
      <script src="https://code.jquery.com/jquery-3.3.1.min.js" integrity="sha256-FgpCb/KJQlLNfOu91ta32o/NMZxltwRo8QtmkMRdAu8=" crossorigin="anonymous"></script>

    <!-- Import Scripts (build in webpack.min.js -->
<script type="text/javascript" src="https://cdn.datatables.net/v/bs/jszip-2.5.0/dt-1.10.16/b-1.5.1/b-colvis-1.5.1/b-flash-1.5.1/b-html5-1.5.1/b-print-1.5.1/r-2.2.1/datatables.min.js"></script>
  <script src="https://hennepinems.org/js/scripts.js"></script>


           <script>
     $(document).ready(function() {
               });
  </script>
  
</body>

</html>