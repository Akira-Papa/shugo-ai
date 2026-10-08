import {invoke} from '@tauri-apps/api/core';
import type {Snapshot} from './types';
export const isDesktop = '__TAURI_INTERNALS__' in window;
export const isDemo = import.meta.env.DEV && new URLSearchParams(location.search).get('demo')==='1';
export async function command<T>(name:string,args:Record<string,unknown>={}):Promise<T>{
 if(isDesktop)return invoke<T>(name,args);
 if(isDemo){const {demoCommand}=await import('./demo');return demoCommand(name,args) as Promise<T>;}
 throw new Error('デスクトップアプリから開いてください。ブラウザーからPC検査はできません。');
}
export const readSnapshot=()=>command<Snapshot>('snapshot');
export const isObservationFresh=(observedAt:number,now=Date.now())=>Number.isFinite(observedAt)&&observedAt<=now&&now-observedAt<=300000;
