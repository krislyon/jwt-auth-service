<template>
    <div>
        <table class="authPropsTable">
            <tr>
                <th>Property</th>
                <th>Value</th>
            </tr>
            <tr>
                <td>Auth Token</td>
                <td>{{user.authToken}}</td>
            </tr>
            <tr>
                <td>userState</td>
                <td>{{user.state.value}}</td>
            </tr>

        </table>
    </div>
</template>

<script>
import { useUser } from '../composables/useUser.js'

export default {
    setup() {
        const user = useUser();
        return { user };
    }
}
</script>

<style>
    .authPropsTable {
        max-width: 1024px;
        table-layout: fixed;
        width: 90%;
        overflow-wrap: break-word;
    }

</style>