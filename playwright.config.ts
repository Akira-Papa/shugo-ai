import {defineConfig} from '@playwright/test';
export default defineConfig({testDir:'./tests',use:{channel:'chrome',baseURL:'http://127.0.0.1:1420',viewport:{width:1280,height:1000},screenshot:'only-on-failure'},webServer:{command:'npm run dev',url:'http://127.0.0.1:1420',reuseExistingServer:true},reporter:[['list'],['json',{outputFile:'test-results/results.json'}]]});
