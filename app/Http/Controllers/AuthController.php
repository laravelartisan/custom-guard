<?php

namespace App\Http\Controllers;

use App\Token;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Http\Request;
use App\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    use AuthenticatesUsers;

//    private $apiToken;

    public function __construct()
    {
        // Unique Token
//        $this->apiToken = uniqid(base64_encode(str_random(60)));
    }


    public function postLogin(Request $request)
    {

        $rules = [
            'email'=>'required|email',
            'password'=>'required|min:3'
        ];
        $validator = Validator::make($request->all(), $rules);
        if ($validator->fails()) {
            // Validation failed
            return response()->json([
                'message' => $validator->messages(),
            ]);
        }else{
            $token = $this->guard()->attempt($this->credentials($request));

            if ($token) {
//                $this->guard()->setToken($token);
                return response()->json([
                    'access_token' => $token->access_token,
                ]);

            }else {
                return response()->json([
                    'message' => 'User not found',
                ]);
            }


        }
    }
    /**
     * Client Login
     */
    public function postLogin__(Request $request)
    {
        // Validations
        $rules = [
            'email'=>'required|email',
            'password'=>'required|min:3'
        ];
        $validator = Validator::make($request->all(), $rules);
        if ($validator->fails()) {
            // Validation failed
            return response()->json([
                'message' => $validator->messages(),
            ]);
        } else {
            // Fetch User
            $user = User::where('email',$request->email)->first();
            if($user) {
                // Verify the password
                if( password_verify($request->password, $user->password) ) {
                    // Update Token
//                    $postArray = ['api_token' => $this->apiToken];
//                    $login = User::where('email',$request->email)->update($postArray);
                   $token =  Token::create([
                        'access_token' => $this->apiToken,
                        'user_id' => $user->id,
                    ]);

                    if($token) {
                        return response()->json([
                            'name'         => $user->name,
                            'email'        => $user->email,
                            'access_token' => $token->access_token,
                        ]);
                    }
                } else {
                    return response()->json([
                        'message' => 'Invalid Password',
                    ]);
                }
            } else {
                return response()->json([
                    'message' => 'User not found',
                ]);
            }
        }
    }
    /**
     * Register
     */
    public function postRegister(Request $request)
    {
        // Validations
        $rules = [
            'name'     => 'required|min:3',
            'email'    => 'required|unique:users,email',
            'password' => 'required|min:3'
        ];
        $validator = Validator::make($request->all(), $rules);
        if ($validator->fails()) {
            // Validation failed
            return response()->json([
                'message' => $validator->messages(),
            ]);
        } else {
            $postArray = [
                'name'      => $request->name,
                'email'     => $request->email,
                'password'  => bcrypt($request->password),
                //'api_token' => $this->apiToken
            ];
//             $user = User::GetInsertId($postArray);

            $user = User::firstOrCreate($postArray);



            if($user) {
                return response()->json([
                    'name'         => $request->name,
                    'email'        => $request->email,
//                    'access_token' => $this->apiToken,
                ]);
            } else {
                return response()->json([
                    'message' => 'Registration failed, please try again.',
                ]);
            }
        }
    }
    /**
     * Logout
     */
    public function postLogout(Request $request)
    {
//        $token = $request->header('Authorization');
//        $user = User::where('api_token',$token)->first();
        $user = auth()->guard('api')->user();
        if($user) {
            $postArray = ['api_token' => null];
            $logout = User::where('id',$user->id)->update($postArray);
            if($logout) {
                return response()->json([
                    'message' => 'User Logged Out',
                ]);
            }
        } else {
            return response()->json([
                'message' => 'User not found',
            ]);
        }
    }
}
