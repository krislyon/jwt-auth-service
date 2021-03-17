<template>
    <div>
      <h2>JWT Auth Sample</h2>
        <button type="button" @click.prevent="handleRequestPublicResource">Request Public Resource</button>
        <button type="button" @click.prevent="handleRequestProtectedResource">Request Protected Resource</button>
        <p>Auth Status: {{authStatus}}</p>
        <p>{{responseStatus}}</p>
        <!-- <p>{{responseHeaders}}</p> -->
        <p>{{responseData.message}}</p>
    </div>
</template>

<script>
// @ is an alias to /src
import { ref, computed } from 'vue'
import axios from '../composables/axiosClient'
import { useUser } from '../composables/useUser'

export default {
  name: 'Home',
  components: {},
  setup(){
    const user = useUser();
    const responseStatus = ref('');
    const responseHeaders = ref('');
    const responseData = ref('');

    const authStatus = computed( () => {
      return user.state.value.loggedIn ? "Logged In" : "Logged Out";
    });

    const updateResponseView = (response) => {
            responseData.value = response.data;
            responseHeaders.value = response.headers;
            responseStatus.value = `HTTP ${response.status} - ${response.statusText}`;
    };

    const handleRequestProtectedResource = async () => {
      axios.get('/protected')
          .then( response => {
            updateResponseView( response );
          })
          .catch( err => {
            updateResponseView( err.response );
          });
    };

    const handleRequestPublicResource = async () => {
          axios.get('/public')
          .then( response => {
            updateResponseView( response );
          })
          .catch( err => {
            updateResponseView( err.response );
          });
    };



    return {
      handleRequestProtectedResource,
      handleRequestPublicResource,
      authStatus,
      responseData,
      responseHeaders,
      responseStatus
    }
  }
}
</script>




