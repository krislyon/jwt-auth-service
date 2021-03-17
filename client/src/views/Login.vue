<template>
  <div>
      <h2>Please Log In</h2>
      <form>
        <label>Username: </label>
        <input type="text" v-model="username"/>
        <label>Password: </label>
        <input type="password" v-model="password"/>
        <button type="button" @click.prevent="performLogin">Sign in</button>
      </form>
  </div>
</template>

<script>
import { ref } from 'vue'
import crypto   from 'crypto';
import axios from '../composables/axiosClient'
import { useUser } from '../composables/useUser';
import { useRouter } from 'vue-router'

export default {
    setup() {
        const username = ref('');
        const password = ref('');
        const router = useRouter();

        const performLogin = async () => {
            // Post to /login to get salt for user
            try {
                let userId = username.value;
                let res = await axios.post( '/login', { userId } );
                if( res.status != 200 ){
                    console.log('Failed to retrieve salt');
                    return;
                }

                // Hash password and send pass for user to /login
                const hash = crypto.createHash('sha256');
                hash.update( res.data.salt + password.value );
                const pwHash = hash.digest().toString('hex');
                res = await axios.post('/login', { pwHash, userId } )

                if( res.status != 200 ){
                    console.log('Failed to log in.');
                    return;
                }

                // Login was successful... login
                var user = useUser();
                user.login({ sampledata: 'test'},res.data.auth_token );

                console.log('Logged In.');
                user = useUser();
                router.push({ name: 'Home' });
            }catch( err ){
                console.log(err);
            }

        }

        return {
            username,
            password,
            performLogin,
        }
    }
}
</script>

<style>

</style>