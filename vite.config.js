import {existsSync} from 'node:fs';
export default {root:existsSync('dist/index.html')?'dist':'.',server:{host:'0.0.0.0',allowedHosts:['terminal.local'],watch:{usePolling:true}}};
