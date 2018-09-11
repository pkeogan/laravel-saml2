	  @foreach(config('saml.sp') as $sp)
	  <div class="hidden">
		  <iframe src="{{ $sp['logout_url'] }}"></iframe>
	  </div>
	  @endforeach