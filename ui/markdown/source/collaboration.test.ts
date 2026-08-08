// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import * as Y from "yjs";
import { MarkdownRealtimeSession } from "./collaboration.js";

describe("Markdown collaboration transport", () => {
  it("authenticates in the first frame, applies the server snapshot, and requests a durable checkpoint", async () => {
    const ServerDocument = new Y.Doc();
    ServerDocument.getText("source").insert(0, "# Durable source\n");
    const Snapshot = Y.encodeStateAsUpdate(ServerDocument);
    const Socket = new FakeWebSocket((Payload) => {
      const FrameNumber = Math.floor((Payload[0] ?? 0) / 8);
      if (FrameNumber === 1) Socket.Receive(Frame(3, Message([Unsigned(2, 0), Unsigned(3, 1), Bytes(4, Snapshot), Unsigned(5, 1)])));
      if (FrameNumber === 11) Socket.Receive(Frame(7, Message([Text(1, "00000000-0000-4000-8000-000000000099"), Unsigned(2, 0), Unsigned(3, 2)])));
    });
    const Connected = MarkdownRealtimeSession.Connect({
      Grant: {
        Authorization: "fbcollab1.test",
        ClientId: "00000000-0000-4000-8000-000000000010",
        EndpointUrl: "wss://files.example.test/collaboration/v1/ws",
        PresenceLabel: "Editor 1",
        RoomId: "00000000-0000-4000-8000-000000000020",
      },
      WebSocketFactory: () => Socket as unknown as WebSocket,
    });
    Socket.Open();
    const Session = await Connected;
    expect(Session.CurrentText()).toBe("# Durable source\n");
    await expect(Session.RequestCheckpoint()).resolves.toBe("00000000-0000-4000-8000-000000000099");
    Session.Destroy();
    ServerDocument.destroy();
  });
});

class FakeWebSocket extends EventTarget {
  readonly #OnSend: (Payload: Uint8Array) => void;
  // eslint-disable-next-line @typescript-eslint/naming-convention -- WebSocket exposes this platform-defined member spelling.
  binaryType = "arraybuffer";
  // eslint-disable-next-line @typescript-eslint/naming-convention -- WebSocket exposes this platform-defined member spelling.
  readyState = 0;

  constructor(OnSend: (Payload: Uint8Array) => void) {
    super();
    this.#OnSend = OnSend;
  }

  Open(): void {
    this.readyState = 1;
    this.dispatchEvent(new Event("open"));
  }

  Receive(Payload: Uint8Array): void {
    queueMicrotask(() => this.dispatchEvent(new MessageEvent("message", { data: Uint8Array.from(Payload).buffer })));
  }

  send(Payload: ArrayBuffer): void {
    this.#OnSend(new Uint8Array(Payload));
  }

  close(): void {
    this.readyState = 3;
    this.dispatchEvent(new Event("close"));
  }
}

const Encoder = new TextEncoder();

function Frame(NumberValue: number, Payload: Uint8Array): Uint8Array {
  return Bytes(NumberValue, Payload);
}

function Message(Parts: Uint8Array[]): Uint8Array {
  const Result = new Uint8Array(Parts.reduce((Total, Part) => Total + Part.byteLength, 0));
  let Offset = 0;
  for (const Part of Parts) {
    Result.set(Part, Offset);
    Offset += Part.byteLength;
  }
  return Result;
}

function Text(NumberValue: number, Value: string): Uint8Array {
  return Bytes(NumberValue, Encoder.encode(Value));
}

function Bytes(NumberValue: number, Value: Uint8Array): Uint8Array {
  return Message([Varint(NumberValue * 8 + 2), Varint(Value.byteLength), Value]);
}

function Unsigned(NumberValue: number, Value: number): Uint8Array {
  return Message([Varint(NumberValue * 8), Varint(Value)]);
}

function Varint(Value: number): Uint8Array {
  const Result: number[] = [];
  let Remaining = Value;
  do {
    const Byte = Remaining % 128;
    Remaining = Math.floor(Remaining / 128);
    Result.push(Byte + (Remaining > 0 ? 128 : 0));
  } while (Remaining > 0);
  return Uint8Array.from(Result);
}
