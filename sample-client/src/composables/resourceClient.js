import axios from 'axios';
import { useUser } from './useUser'
import { authClient } from './authClient'


const axiosClient = () => {

  const defaultOptions = {
    baseURL: 'https://localhost:3100',
    withCredentials: true,
    json: true,
    headers: {
      'Content-Type': 'application/json',
    },
  };

  // Create instances
  let instance = axios.create(defaultOptions);

  instance.interceptors.request.use(function (config) {
    // If the user is signed in and there is an auth token set,
    // include it in the request as a Bearer token.
    const user = useUser();
    if( user.authToken != "" ){
      config.headers.Authorization =  `Bearer ${user.authToken}`;
    }
    return config;
  });

  instance.interceptors.response.use( res => res, async err => {
    var user = useUser();
    const originalRequest = err.config;
    // If it was an authorization error and we haven't already retried...
    if( err.response.status === 401 && !originalRequest._retry && originalRequest.url !== '/refresh' ){
      originalRequest._retry = true;
      return authClient.post('/refresh')
        .then( result => {
          if( result && result.status === 200 ){
            user.refresh( result.data.auth_token );
            return instance( originalRequest );
          }
          return result.response;
        })
    }

    if( err.response.status === 401 && originalRequest.url === '/refresh' ){
      user.logout();
    }

    return err;
  });

  return instance;
};

export default axiosClient();