import {SqttService} from './gen/sqtt/v2/sqtt_connectweb'
import { createGrpcWebTransport, createPromiseClient } from '@bufbuild/connect-web'

const transport = createGrpcWebTransport({
  baseUrl: 'http://localhost:50051'
})

export const grpcClient = createPromiseClient(SqttService, transport)
