# LinOTP Authentication Plugin

This plugin enables 2FA authentication against [LinOTP](https://linotp.org).
User logins are verified against LinOTP. Depending on the LinOTP configuration
additional credentials will be asked for.

For more information about configuring LinOTP see the [Management guide](https://www.linotp.org/doc/latest/part-management).

## Configuration

### Create admin user

You need to ensure that the initial user is already present in the database.
You can do this by running the UserInit command:

    /var/www/MISP/app/Console/cake UserInit


### Load the plugin

Enable the `LinOTPAuth` plugin in `app/config/bootstrap.php`

The bootstrap file contains a line similar to the line below.
Uncomment it to load the Plugin:

```php
CakePlugin::load('LinOTPAuth');
```

### Plugin configuration

The following modifications are required in `app/Config/config.php`

1. Add a `LinOTPAuth` section to your `config.php` as shown in
`app/config/config.default.php`.

    ```php
    'LinOTPAuth' => // Configuration for the LinOTP authentication
        array(
            'baseUrl'      => 'https://linotp', // The base URL of LinOTP
            'realm'        => 'lino',           // the (default) realm of all the users logging in through this system
            'userModel'    => 'User',           // name of the User class (MISP class) to check if the user exists
            'userModelKey' => 'email',          // User field that will be used for querying.
        ),
    ```

1. Add the module to the `Security.Auth` list.

    Within the `Security` array add another key
    `auth` with the value `array("LinOTPAuth.LinOTP")`.  The entire `Security`
    array might then look similar to the example displayed below.

    ```php
    'Security' =>
        array(
            'level'      => 'medium',
            'salt'       => 'SOME SEED',
            'cipherSeed' => 'SOME OTHER SEED',
            'auth'=>array('LinOTPAuth.LinOTP'),
        ),
    ```

    Your MISP installation will most likely already have values on the `salt`
    and `cipherSeed` fields. Leave them as they are. The values displayed above
    are just placeholders.

### Configure LinOTP

#### SQL Resolver

LinOTP needs to be able to read the users and their passwords directly from the MISP database. In
order to set these up, navigate to the manage page of your linotp instance (`https://linotp/manage`)
and log in.

LinOTP should be configured with a SQL Resolver to use the MISP database directly:

* Create a new resolver: LinOTP Config → Resolvers → New → SQL

    * Driver: mysql
    * Server: MISP Database hostname
    * Port: 3306 or port number that the database is listening on

* These values should match the configuration of the database:

    * Database: Database name e.g. (misp)
    * User: Database user name
    * Password: Database password
    * Database table: `users`
    * Attribute mapping: `{ "userid" : "id", "username": "email","password" : "password" }`

* Click 'Test SQL connection' to test

#### Realm

The defined user resolver should be added to the Realm defined in the MISP configuration above.

#### Tokens

Tokens should be added ('enroll') and associated with users ('assign')
