<?php

namespace KingStarter\LaravelSaml\Console;

use App\Http\Middleware\SamlAuth;
use function GuzzleHttp\Psr7\str;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Storage;
use neilherbertuk\modules\Traits\MakeController;
use neilherbertuk\modules\Traits\MakeModule;
use neilherbertuk\modules\Traits\MakeRoutes;

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
    }

    protected function generateCertificate()
    {
        $keyfile = Storage::disk('saml')->path(config('saml.idp.key'));
        $certfile = Storage::disk('saml')->path(config('saml.idp.cert'));
        $days = $this->options()['cert-days'];

        if($this->options()['cert'] || !file_exists($keyfile) || !file_exists($certfile)){
            $output = [];
            $ret = 0;
            exec("openssl req -newkey rsa:2048 -nodes -x509 -days $days -out $certfile -keyout $keyfile ",
                $output,$ret );
            if($ret == 0){
                $this->info("Certificate Generated");
            }else{
                $this->error("Failed to generate certificate\n". implode("\n", $output));
            }
        }

    }

    protected function generateMetadata()
    {
        $metadataFile = Storage::disk('saml')->path(config('saml.idp.metadata'));
        $file = pathinfo($metadataFile);
        $blade = $file['dirname'].'/'.$file['filename'].'.blade.php';

        $certificate = file_get_contents( Storage::disk('saml')->path(config('saml.idp.cert')));
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

        $this->info("$metadataFile generated");
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

}