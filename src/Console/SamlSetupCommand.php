<?php

namespace Pkeogan\LaravelSaml\Console;

use App\Http\Middleware\SamlAuth;
use function GuzzleHttp\Psr7\str;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Storage;
use neilherbertuk\modules\Traits\MakeController;
use neilherbertuk\modules\Traits\MakeModule;
use neilherbertuk\modules\Traits\MakeRoutes;
use LightSaml\Credential\X509Certificate;

use RobRichards\XMLSecLibs\XMLSecurityKey; //https://github.com/robrichards/xmlseclibs/blob/master/src/XMLSecurityKey.php
use RobRichards\XMLSecLibs\XMLSecurityDSig; //https://github.com/robrichards/xmlseclibs/blob/master/src/XMLSecurityDSig.php


class SamlSetupCommand extends Command
{

    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'laravel-saml:generate-meta {--cert} {--cert-days=100000}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Sets up IDP metadata';

    /**
     * Create a new command instance.
     *
     */
    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Execute the console command.
     *
     * @return mixed
     */
    public function handle()
    {
        //Check disk
        try{
            Storage::disk('saml');
        }catch(\InvalidArgumentException $ex){
            throw new \Exception('saml disk not configured in config/filesystems.php');
        }
		

		$this->generateCertificate();			
        $this->generateMetadata();
		if(config('saml.metadata.sign_metadata')){
			$this->signMetadata();
		}
		
    }

    protected function generateCertificate()
    {
		//gerneate the openssl.cnf file, and save it
		Storage::disk('saml')->put(config('saml.openssl_config_location'), $this->arr2ini(config('saml.openssl_config')));
		$config = Storage::disk('saml')->path(config('saml.openssl_config_location'));
		$first = false;
		$m_first = false;
		//check if the cert and key exist, if they dont make a blank file so we can create it
		if(!Storage::disk('saml')->exists(config('saml.metadata.cert'))){
			Storage::disk('saml')->put(config('saml.metadata.cert'), '');
			$first = true;
		} 
		if(!Storage::disk('saml')->exists(config('saml.metadata.key'))) {
			$first = true;
			Storage::disk('saml')->put(config('saml.metadata.key'), '');
		}
		$certfile = Storage::disk('saml')->path(config('saml.metadata.cert'));
		$keyfile = Storage::disk('saml')->path(config('saml.metadata.key'));

		//check if we are going to sign the metadata, if so, lets make the blank ones
		if(config('saml.metadata.sign_metadata')){
			//overwrtie old certs and make them blank
			if(!Storage::disk('saml')->exists(config('saml.metadata.sign_metadata_cert'))) {
				Storage::disk('saml')->put(config('saml.metadata.sign_metadata_cert'), '');
				$m_first = true;
			}
			if(!Storage::disk('saml')->exists(config('saml.metadata.sign_metadata_key'))) {
				Storage::disk('saml')->put(config('saml.metadata.sign_metadata_key'), '');
				$m_first = true;
			}
			$m_certfile = Storage::disk('saml')->path(config('saml.metadata.sign_metadata_cert'));
			$m_keyfile = Storage::disk('saml')->path(config('saml.metadata.sign_metadata_key'));
		}
			

        if($this->options()['cert'] || $first){

            $output = [];
            $ret = 0;
            exec("openssl req -new -x509 -config $config -out $certfile -keyout $keyfile ",
                $output,$ret );
            if($ret == 0){
                $this->info("IDP Certificate Generated");
            }else{
                $this->error("Failed to generate certificate\n". implode("\n", $output));
            }
        }
		
		//if we are signing meta data, then lets make the certs now
		if(config('saml.metadata.sign_metadata')){
			if($this->options()['cert'] || $m_first){
				$output = [];
				$ret = 0;
				exec("openssl req -new -x509 -config $config -out $m_certfile -keyout $m_keyfile ",
					$output,$ret );
				if($ret == 0){
					$this->info("Metadata Certificate Generated");
				}else{
					$this->error("Failed to generate certificate\n". implode("\n", $output));
				}
			}
		}
		
		if(!$this->options()['cert'] && !$first && !$m_first)
		{
			$this->info("No Certificates Generated, use the --cert flag to overwrite the old ones");
		}
		

    }

    protected function generateMetadata()
    {
		

		
		//create the metadata file
        $metadataFile = Storage::disk('saml')->path(config('saml.metadata.location'));
        $file = pathinfo($metadataFile);
        $blade = $file['dirname'].'/'.$file['filename'].'.blade.php';

        $certificate = file_get_contents( Storage::disk('saml')->path(config('saml.metadata.cert')));
        $certificate = preg_replace('/-----.*CERTIFICATE-----/', '', $certificate);
        $certificate = str_replace("\n","", $certificate);

        if(file_exists($blade)){
            $contents = $this->bladeRender(file_get_contents($blade), [
                'certificate' => $certificate
            ]);
            file_put_contents($metadataFile, $contents);
        }else{
            throw new \Exception("File $blade doesn't exist");
        }

        $this->info("metadata generated");
    }
	
	private function signMetadata()
	{

		// Load in both certificate and keyfile
        // The files are stored within a private storage path, this prevents from
        // making them accessible from outside  
        $x509 = new X509Certificate();
        $certificate = $x509->loadPem(Storage::disk('saml')->get(config('saml.metadata.sign_metadata_cert')));
        // Load in keyfile content (last parameter determines of the first one is a file or its content)
				//dd($this->keyfile());
        $privateKey = \LightSaml\Credential\KeyHelper::createPrivateKey(Storage::disk('saml')->path(config('saml.metadata.sign_metadata_key')), 
																		config('saml.metadata.sign_metadata_key_passphrase'), 
																		true, 
																		XMLSecurityKey::RSA_SHA256);
		
		$signature = new \LightSaml\Model\XmlDSig\SignatureWriter($certificate, $privateKey, XMLSecurityDSig::SHA256);
		
		$metadataFile = Storage::disk('saml')->path(config('saml.metadata.location'));
        $file = pathinfo($metadataFile);

		
		$metadata = \LightSaml\Model\Metadata\Metadata::fromFile($metadataFile);
		
		$metadata->setSignature($signature);
		
		$serializationContext = new \LightSaml\Model\Context\SerializationContext();
		
		$metadata->serialize($serializationContext->getDocument(), $serializationContext);
		
		
		Storage::disk('saml')->put(config('saml.metadata.location'), $serializationContext->getDocument()->saveXML());

		 $this->info("metadata signed");
	}

    public function bladeRender($value, array $args = array())
    {
        $generated = \Blade::compileString($value);

        ob_start() and extract($args, EXTR_SKIP);

        // We'll include the view contents for parsing within a catcher
        // so we can avoid any WSOD errors. If an exception occurs we
        // will throw it out to the exception handler.
        try
        {
            eval('?>'.$generated);
        }
        catch (\Exception $e)
        {
            // If we caught an exception, we'll silently flush the output
            // buffer so that no partially rendered views get thrown out
            // to the client and confuse the user with junk.
            ob_get_clean(); throw $e;
        }

        $content = ob_get_clean();

        return $content;
    }
	
	function arr2ini(array $a, array $parent = array())
	{
		$out = '';
		foreach ($a as $k => $v)
		{
			if (is_array($v))
			{
				//subsection case
				//merge all the sections into one array...
				$sec = array_merge((array) $parent, (array) $k);
				//add section information to the output
				$out .= '[' . join('.', $sec) . ']' . PHP_EOL;
				//recursively traverse deeper
				$out .= $this->arr2ini($v, $sec);
			}
			else
			{
				//plain key->value case
				$out .= "$k=$v" . PHP_EOL;
			}
		}
		return $out;
	}


}