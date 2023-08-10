# Terraform State Backend for Cloudflare R2

This is a `.tfstate` backend running as a Cloudflare worker, storing the
state in a R2 bucket. It supports locking.

## Deployment

To use this backend, you'll need to deploy the worker to the Cloudflare account
where the bucket is located.

### Create R2 bucket

Create the R2 bucket if it does not already exist.

```shell
npx wrangler r2 bucket create <NAME>
```

### Create pre-shared key for authenticating to APIs

Generate a secure shared key, using a command like below:

```shell
pwgen --symbols --secure 512 1
```

Create the secret (the worker expects the name `PSK`, Wrangler
will prompt you to enter the secret value):

```shell
npx wrangler secret put PSK
```

### Configure wrangler.toml

Copy the `wrangler.toml.example` file to `wrangler.toml`, then modify
it to suit your environment.

See <https://developers.cloudflare.com/workers/wrangler/configuration/> for
more details on the configuration settings.

### Deploy the worker

Run `npx wrangler deploy` to deploy it to Cloudflare.

### Test the worker

You can verify that it has worked by calling `https://<YOUR_HOST>/health`,
if it worked, and the secret `PSK` and var `BUCKET` were present,
you will see the string `UP` as the response.

## Configuration

To use this backend in Terraform, you need to use the `http` backend, as follows,
where `<YOUR_HOST>` is the host your worker is deployed at, and `<NAME>` is
a name for the Terraform state file (without the `.tfstate` suffix).

The user name can be anything, it will be ignored.

The password should be the value of the `PSK` secret created above.

Of course, don't store it in your Terraform file, but pass it in via a
variable or read it from a secret store like Vault.

```hcl
backend "http" {
  address        = "https://<YOUR_HOST>/state/<NAME>"
  lock_address   = "https://<YOUR_HOST>/states/hello-world/lock"
  unlock_address = "https://<YOUR_HOST>/states/hello-world/lock"
  username       = "anything"
  password       = "<PSK>"
}
```

## Credits

The blog
post [Implementing a Terraform state backend](https://mirio.dev/2022/09/18/implementing-a-terraform-state-backend/)
on Cloudflare workers was super useful, and I basically cribbed the approach, but implemented the worker myself as a pet
project.
