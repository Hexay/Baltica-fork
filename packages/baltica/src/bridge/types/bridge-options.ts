import type { Socks5Options } from "@baltica/raknet";
import { defaultServerOptions, type ServerOptions } from "../../server";

export type BridgeOptions = ServerOptions & {
   destination: {
      address: string;
      port: number;
   };
   offline: boolean;
   proxy?: Socks5Options;
   email?: string;
   password?: string;
};

export const defaultBridgeOptions: BridgeOptions = {
   ...defaultServerOptions,
   destination: {
      address: "127.0.0.1",
      port: 19132,
   },
   offline: false,
};
