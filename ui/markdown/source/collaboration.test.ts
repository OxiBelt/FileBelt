// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import * as Y from "yjs";
import { MarkdownRealtimeSession } from "./collaboration.js";

describe("Markdown collaboration transport", () => {
  it("authenticates in the first frame, applies the server snapshot, and requests a durable checkpoint", async () => {
    const ServerDocument = new Y.Doc();
    ServerDocument.getText("source").insert(0, "# Durable source\n");
    const Snapshot = Y.encodeStateAsUpdate(ServerDocument);
    let SessionReference: MarkdownRealtimeSession | undefined;
    const Socket = new FakeWebSocket((Payload) => {
      const FrameNumber = Math.floor((Payload[0] ?? 0) / 8);
      if (FrameNumber === 1)
        Socket.Receive(
          Frame(3, Message([Unsigned(2, 0), Unsigned(3, 1), Bytes(4, Snapshot), Unsigned(5, 1)])),
        );
      if (FrameNumber === 11) {
        SessionReference?.Document.getText("source").insert(
          SessionReference.CurrentText().length,
          "later edit\n",
        );
        Socket.Receive(
          Frame(
            7,
            Message([
              Text(1, "00000000-0000-4000-8000-000000000099"),
              Unsigned(2, 0),
              Unsigned(3, 2),
            ]),
          ),
        );
      }
    });
    const Connected = MarkdownRealtimeSession.Connect({
      Grant: {
        Authorization: "fbcollab1.test",
        ClientId: "00000000-0000-4000-8000-000000000010",
        EndpointUrl: "wss://files.example.test/collaboration/v1/ws",
        PresenceLabel: "Editor 1",
        RoomId: "00000000-0000-4000-8000-000000000020",
      },
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- The EventTarget-based test transport deliberately implements only the WebSocket members this harness exercises.
      WebSocketFactory: () => Socket as unknown as WebSocket,
    });
    Socket.Open();
    const Session = await Connected;
    SessionReference = Session;
    expect(Session.CurrentText()).toBe("# Durable source\n");
    const Checkpoint = await Session.RequestCheckpoint();
    expect(Checkpoint).toMatchObject({
      Id: "00000000-0000-4000-8000-000000000099",
      Source: "# Durable source\n",
    });
    expect(Session.CurrentText()).toBe("# Durable source\nlater edit\n");
    expect(Checkpoint.StateVector).not.toEqual(Session.CurrentStateVector());
    Session.Destroy();
    ServerDocument.destroy();
  });

  it("uses an application close code after a server protocol rejection", async () => {
    const Socket = new FakeWebSocket(() => undefined);
    const Connected = MarkdownRealtimeSession.Connect({
      Grant: {
        Authorization: "fbcollab1.test",
        ClientId: "00000000-0000-4000-8000-000000000010",
        EndpointUrl: "wss://files.example.test/collaboration/v1/ws",
        PresenceLabel: "Editor 1",
        RoomId: "00000000-0000-4000-8000-000000000020",
      },
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- The EventTarget-based test transport deliberately implements only the WebSocket members this harness exercises.
      WebSocketFactory: () => Socket as unknown as WebSocket,
    });
    Socket.Open();
    Socket.Receive(Frame(9, Message([Unsigned(1, 8), Text(2, "rejected")])));
    await expect(Connected).rejects.toThrow("The collaboration transport closed.");
    expect(Socket.CloseCodes[0]).toBe(4008);
  });
});

class FakeWebSocket extends EventTarget {
  // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- The test transport preserves its mutable byte-buffer harness contract.
  readonly #OnSend: (Payload: Uint8Array) => void;
  // oxlint-disable-next-line filebelt/pascal-case -- WebSocket exposes this platform-defined member spelling.
  binaryType = "arraybuffer";
  // oxlint-disable-next-line filebelt/pascal-case -- WebSocket exposes this platform-defined member spelling.
  readyState = 0;
  readonly CloseCodes: (number | undefined)[] = [];

  // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- The test transport preserves its mutable byte-buffer harness contract.
  constructor(OnSend: (Payload: Uint8Array) => void) {
    super();
    this.#OnSend = OnSend;
  }

  Open(): void {
    this.readyState = 1;
    this.dispatchEvent(new Event("open"));
  }

  // oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- The test transport preserves its mutable byte-buffer harness contract.
  Receive(Payload: Uint8Array): void {
    queueMicrotask(() => {
      this.dispatchEvent(new MessageEvent("message", { data: Uint8Array.from(Payload).buffer }));
    });
  }

  send(Payload: ArrayBuffer): void {
    this.#OnSend(new Uint8Array(Payload));
  }

  close(Code?: number): void {
    this.CloseCodes.push(Code);
    this.readyState = 3;
    this.dispatchEvent(new Event("close"));
  }
}

const Encoder = new TextEncoder();

// oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- The test wire helper preserves its mutable byte-buffer harness contract.
function Frame(NumberValue: number, Payload: Uint8Array): Uint8Array {
  return Bytes(NumberValue, Payload);
}

// oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- The test wire helper preserves its mutable byte-buffer harness contract.
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

// oxlint-disable-next-line typescript/prefer-readonly-parameter-types -- The test wire helper preserves its mutable byte-buffer harness contract.
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
