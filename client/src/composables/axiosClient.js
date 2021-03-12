import axios from 'axios';
import { useUser } from '../composables/useUser'


const axiosClient = () => {
  const defaultOptions = {
    baseURL: 'https://localhost:3000',
    json: true,
    headers: {
      'Content-Type': 'application/json',
    }
  };

  // Create instance
  let instance = axios.create(defaultOptions);

  // Set the AUTH token for any request
  instance.interceptors.request.use(function (config) {
    const user = useUser();
    if( user.authToken != "" ){
      config.headers.Authorization =  `Bearer ${user.authToken}`;
    }
    return config;
  });

  return instance;
};

export default axiosClient();