<?php

namespace App\Custom;

use App\Token;
use App\User;
use Illuminate\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Support\Str;


class CustomUserProvider implements  UserProvider
{

    private $token;
    private $user;
    private $accessToken;

    public function __construct (User $user, Token $token) {
        $this->user = $user;
        $this->token = $token;
        $this->accessToken = uniqid(base64_encode(str_random(60)));
    }
    public function retrieveById ($identifier) {
        return $this->user->find($identifier);
    }
    public function retrieveByToken ($identifier, $token) {
        $token = $this->token->with('user')->where($identifier, $token)->first();
        return $token && $token->user ? $token->user : null;
    }
    public function updateRememberToken (\Illuminate\Contracts\Auth\Authenticatable $user, $token) {
        // update via remember token not necessary
    }

    public function retrieveByCredentials(array $credentials)
    {
        $query = $this->user->newQuery();
        foreach ($credentials as $key => $value) {
            if (Str::contains($key, 'password')) {
                continue;
            }

            if (is_array($value) || $value instanceof Arrayable) {
                $query->whereIn($key, $value);
            } else {
                $query->where($key, $value);
            }
        }

        return $query->first();
    }

    /**
     *
     */
    public function login(User $user)
    {
        $token =  $this->token->create([
            'access_token' => $this->accessToken,
            'user_id' => $user->id,
        ]);

        return $token;
    }
    public function retrieveByCredentials__ (array $credentials) {
        // implementation upto user.
        // how he wants to implement -
        // let's try to assume that the credentials ['username', 'password'] given
        $user = $this->user;
        foreach ($credentials as $credentialKey => $credentialValue) {
            if (!Str::contains($credentialKey, 'password')) {
                $user->where($credentialKey, $credentialValue);
            }
        }
        return $user->first();
    }
    public function validateCredentials (\Illuminate\Contracts\Auth\Authenticatable $user, array $credentials) {
        $plain = $credentials['password'];
        return app('hash')->check($plain, $user->getAuthPassword());
    }
}