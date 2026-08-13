// SPDX-License-Identifier: Apache-2.0

import * as Encoding from "lib0/encoding";
import { applyAwarenessUpdate, Awareness } from "y-protocols/awareness";
import * as Y from "yjs";
import type { TextCollaboration } from "./editor.js";

const Encoder = new TextEncoder();
const Decoder = new TextDecoder("utf-8", { fatal: true });
const MaximumFrameBytes = 2 * 1024 * 1024 + 64 * 1024;
const MaximumChunkBytes = 256 * 1024;
const OpenWebSocketState = 1;
const RemoteDocumentOrigin = Symbol("filebelt-remote-document");
const RemoteAwarenessOrigin = Symbol("filebelt-remote-awareness");
const McpProposalOrigin = Symbol("filebelt-mcp-proposal");
const Colors = ["#0078d4", "#107c10", "#d83b01", "#5c2d91", "#008272", "#c239b3", "#ca5010", "#038387"] as const;

// Yjs awareness events and serialized cursor state define these lower-camel wire keys.
type AwarenessChange = Record<"added", number[]> & Record<"removed", number[]> & Record<"updated", number[]>;
type AwarenessCursor = Record<"anchor", unknown> & Record<"head", unknown>;
type AwarenessLocalState = Record<"cursor", AwarenessCursor>;

export interface MarkdownCollaborationGrant {
  Authorization: string;
  ClientId: string;
  EndpointUrl: string;
  PresenceLabel: string;
  RoomId: string;
}

export type MarkdownCollaborationState = "connected" | "connecting" | "disconnected";

export interface ConnectMarkdownCollaborationOptions {
  Grant: MarkdownCollaborationGrant;
  OnStateChange?: (State: MarkdownCollaborationState) => void;
  WebSocketFactory?: (Url: string) => WebSocket;
}

export class MarkdownRealtimeSession implements TextCollaboration {
  readonly Awareness: Awareness;
  readonly Document: Y.Doc;
  readonly TextName = "source";
  readonly #Grant: MarkdownCollaborationGrant;
  readonly #OnStateChange: ((State: MarkdownCollaborationState) => void) | undefined;
  readonly #RemoteClients = new Map<string, { AwarenessId: number; Clock: number }>();
  readonly #Socket: WebSocket;
  #AcknowledgedSequence = 0;
  #Destroyed = false;
  #Failed = false;
  #Heartbeat: ReturnType<typeof setInterval> | undefined;
  #InitialSync: ChunkAccumulator | undefined;
  #InFlight: { Id: string; McpInvocationId?: string; Update: Uint8Array } | undefined;
  #PendingUpdates: { McpInvocationId?: string; Update: Uint8Array }[] = [];
  #PendingCheckpoint: { Reject: (Reason?: unknown) => void; Resolve: (Id: string) => void } | undefined;
  #Ready = false;

  private constructor(Options: ConnectMarkdownCollaborationOptions, Socket: WebSocket) {
    this.#Grant = Options.Grant;
    this.#OnStateChange = Options.OnStateChange;
    this.#Socket = Socket;
    this.Document = new Y.Doc();
    this.Awareness = new Awareness(this.Document);
  }

  static async Connect(Options: ConnectMarkdownCollaborationOptions): Promise<MarkdownRealtimeSession> {
    const Socket = (Options.WebSocketFactory ?? ((Url: string) => new WebSocket(Url)))(Options.Grant.EndpointUrl);
    Socket.binaryType = "arraybuffer";
    const Session = new MarkdownRealtimeSession(Options, Socket);
    Options.OnStateChange?.("connecting");
    try {
      await Session.#Open();
      return Session;
    } catch (Cause) {
      Session.Destroy();
      throw Cause;
    }
  }

  CurrentText(): string {
    return this.Document.getText(this.TextName).toString();
  }

  ApplyMcpProposal(Markdown: string, InvocationId: string): void {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(InvocationId)) throw new Error("The MCP invocation identifier is invalid.");
    const SharedText = this.Document.getText(this.TextName);
    this.Document.transact(() => {
      SharedText.delete(0, SharedText.length);
      SharedText.insert(0, Markdown);
    }, { InvocationId, Type: McpProposalOrigin });
  }

  ApplyReconnectMerge(Markdown: string): void {
    const SharedText = this.Document.getText(this.TextName);
    this.Document.transact(() => {
      SharedText.delete(0, SharedText.length);
      SharedText.insert(0, Markdown);
    });
  }

  async RequestCheckpoint(): Promise<string> {
    if (!this.#Ready || this.#Destroyed || this.#InFlight !== undefined || this.#PendingUpdates.length > 0 || this.#PendingCheckpoint !== undefined) {
      throw new Error("Collaboration changes must be durable before saving.");
    }
    return new Promise<string>((Resolve, Reject) => {
      this.#PendingCheckpoint = { Reject, Resolve };
      this.#Send(Frame(11, Message([Unsigned(1, this.#AcknowledgedSequence)])));
    });
  }

  Destroy(): void {
    if (this.#Destroyed) return;
    this.#Destroyed = true;
    this.#Ready = false;
    if (this.#Heartbeat !== undefined) clearInterval(this.#Heartbeat);
    this.Document.off("update", this.#DocumentUpdate);
    this.Awareness.off("update", this.#AwarenessUpdate);
    this.#PendingCheckpoint?.Reject(new Error("The collaboration session ended."));
    this.#PendingCheckpoint = undefined;
    this.#Socket.close(1000, "view closed");
    this.Awareness.destroy();
    this.Document.destroy();
    this.#OnStateChange?.("disconnected");
  }

  async #Open(): Promise<void> {
    await new Promise<void>((Resolve, Reject) => {
      let Settled = false;
      const Fail = (Reason: unknown): void => {
        if (!Settled) {
          Settled = true;
          Reject(Reason);
        }
      };
      this.#Socket.addEventListener("open", () => {
        try {
          this.#Send(Frame(1, Message([
            Bytes(1, Encoder.encode(this.#Grant.Authorization)),
            Text(2, this.#Grant.RoomId),
            Unsigned(3, 1),
            Unsigned(4, 1),
          ])));
        } catch (Cause) {
          Fail(Cause);
        }
      }, { once: true });
      this.#Socket.addEventListener("message", (Event) => {
        try {
          const Bytes = Event.data instanceof ArrayBuffer ? new Uint8Array(Event.data) : new Uint8Array();
          this.#Receive(Bytes);
          if (this.#Ready && !Settled) {
            Settled = true;
            Resolve();
          }
        } catch (Cause) {
          Fail(Cause);
          this.#Fail(Cause);
        }
      });
      this.#Socket.addEventListener("error", () => Fail(new Error("The collaboration transport failed.")), { once: true });
      this.#Socket.addEventListener("close", () => {
        const ErrorValue = new Error("The collaboration transport closed.");
        Fail(ErrorValue);
        this.#Fail(ErrorValue);
      });
    });
  }

  #Start(): void {
    this.#Ready = true;
    this.Document.on("update", this.#DocumentUpdate);
    this.Awareness.on("update", this.#AwarenessUpdate);
    this.Awareness.setLocalStateField("user", {
      color: Colors[HashUuid(this.#Grant.ClientId) % Colors.length],
      name: this.#Grant.PresenceLabel,
    });
    this.#Heartbeat = setInterval(() => {
      if (this.#Socket.readyState !== OpenWebSocketState) return;
      this.#Send(Frame(10, Message([
        Unsigned(1, this.#AcknowledgedSequence),
        Unsigned(2, Date.now()),
      ])));
      this.#SendAwareness(2);
    }, 15_000);
    this.#OnStateChange?.("connected");
  }

  readonly #DocumentUpdate = (Update: Uint8Array, Origin: unknown): void => {
    if (Origin === RemoteDocumentOrigin || !this.#Ready || this.#Destroyed) return;
    if (Update.byteLength === 0 || Update.byteLength > 2 * 1024 * 1024) {
      this.#Fail(new Error("The collaboration update exceeds the supported limit."));
      return;
    }
    const McpInvocationId = IsMcpProposalOrigin(Origin) ? Origin.InvocationId : undefined;
    this.#PendingUpdates.push({ ...(McpInvocationId === undefined ? {} : { McpInvocationId }), Update });
    this.#Pump();
  };

  readonly #AwarenessUpdate = ({ added: Added, removed: Removed, updated: Updated }: AwarenessChange, Origin: unknown): void => {
    if (Origin === RemoteAwarenessOrigin || this.#Destroyed) return;
    const LocalId = this.Document.clientID;
    if (Removed.includes(LocalId)) this.#SendAwareness(3);
    else if (Added.includes(LocalId)) this.#SendAwareness(1);
    else if (Updated.includes(LocalId)) this.#SendAwareness(2);
  };

  #Pump(): void {
    if (this.#InFlight !== undefined || this.#Socket.readyState !== OpenWebSocketState) return;
    const Pending = this.#PendingUpdates.shift();
    if (Pending === undefined) return;
    const { McpInvocationId, Update } = Pending;
    const Id = crypto.randomUUID();
    this.#InFlight = { Id, ...(McpInvocationId === undefined ? {} : { McpInvocationId }), Update };
    const Chunks = Array.from({ length: Math.ceil(Update.byteLength / MaximumChunkBytes) }, (Ignored, Index) => {
      const Start = Index * MaximumChunkBytes;
      return Message([Unsigned(1, Index), Bytes(2, Update.slice(Start, Start + MaximumChunkBytes))]);
    });
    this.#Send(Frame(4, Message([
      Text(1, Id),
      Unsigned(2, this.#AcknowledgedSequence),
      ...Chunks.map((Chunk) => Bytes(3, Chunk)),
      ...(McpInvocationId === undefined ? [] : [Text(4, McpInvocationId)]),
    ])));
  }

  #Receive(BytesValue: Uint8Array): void {
    if (BytesValue.byteLength === 0 || BytesValue.byteLength > MaximumFrameBytes) throw new Error("Invalid collaboration frame.");
    const Outer = Fields(BytesValue);
    const Active = Outer.find((Field) => Field.Wire === 2);
    if (Active?.Bytes === undefined) throw new Error("Empty collaboration frame.");
    switch (Active.Number) {
      case 3: this.#ReceiveSync(Fields(Active.Bytes)); break;
      case 5: this.#ReceiveAcknowledgement(Fields(Active.Bytes)); break;
      case 6: this.#ReceiveAwareness(Fields(Active.Bytes)); break;
      case 7: this.#ReceiveCheckpoint(Fields(Active.Bytes)); break;
      case 8: this.#Fail(new Error("The collaboration room was frozen.")); break;
      case 9: this.#Fail(new Error(StringField(Fields(Active.Bytes), 2) || "The collaboration server rejected the request.")); break;
      case 10: break;
      default: throw new Error("Unsupported collaboration frame.");
    }
  }

  #ReceiveSync(Values: WireField[]): void {
    const Sequence = NumberField(Values, 1);
    const Index = NumberField(Values, 2);
    const Count = NumberField(Values, 3);
    const Update = BytesField(Values, 4);
    const Snapshot = NumberField(Values, 5) === 1;
    if (Count < 1 || Count > 16 || Index >= Count || Update.byteLength > MaximumChunkBytes) throw new Error("Invalid collaboration sync group.");
    const Current = this.#InitialSync;
    if (Current !== undefined && (Current.Sequence !== Sequence || Current.Snapshot !== Snapshot)) throw new Error("Interleaved collaboration sync groups are not permitted.");
    const Accumulator = Current !== undefined && Current.Sequence === Sequence && Current.Snapshot === Snapshot
      ? Current
      : { Chunks: new Array<Uint8Array | undefined>(Count), Sequence, Snapshot };
    if (Accumulator.Chunks.length !== Count || Accumulator.Chunks[Index] !== undefined) throw new Error("Invalid collaboration sync ordering.");
    Accumulator.Chunks[Index] = Update;
    this.#InitialSync = Accumulator;
    if (Accumulator.Chunks.some((Chunk) => Chunk === undefined)) return;
    const Complete = Concatenate(Accumulator.Chunks as Uint8Array[]);
    this.#InitialSync = undefined;
    if (Complete.byteLength > 2 * 1024 * 1024) throw new Error("Collaboration sync group exceeds the supported limit.");
    if (!this.#Ready) {
      if (!Snapshot) throw new Error("Initial collaboration sync must be a snapshot.");
      if (Complete.byteLength > 0) Y.applyUpdate(this.Document, Complete, RemoteDocumentOrigin);
      this.#AcknowledgedSequence = Sequence;
      this.#Start();
      return;
    }
    if (Snapshot) throw new Error("Unexpected collaboration snapshot.");
    if (Sequence <= this.#AcknowledgedSequence) return;
    if (Sequence !== this.#AcknowledgedSequence + 1) throw new Error("Collaboration sync sequence skipped a durable group.");
    if (Complete.byteLength > 0) Y.applyUpdate(this.Document, Complete, RemoteDocumentOrigin);
    this.#AcknowledgedSequence = Sequence;
  }

  #ReceiveAcknowledgement(Values: WireField[]): void {
    const Id = StringField(Values, 1);
    const Sequence = NumberField(Values, 2);
    if (this.#InFlight?.Id !== Id || Sequence < this.#AcknowledgedSequence || Sequence > this.#AcknowledgedSequence + 1) throw new Error("Invalid collaboration acknowledgement.");
    this.#AcknowledgedSequence = Sequence;
    this.#InFlight = undefined;
    this.#Pump();
  }

  #ReceiveCheckpoint(Values: WireField[]): void {
    const Id = StringField(Values, 1);
    const Sequence = NumberField(Values, 2);
    const State = NumberField(Values, 3);
    if (this.#PendingCheckpoint === undefined || State !== 2 || Sequence !== this.#AcknowledgedSequence || Id.length === 0) {
      throw new Error("Invalid collaboration checkpoint.");
    }
    const Pending = this.#PendingCheckpoint;
    this.#PendingCheckpoint = undefined;
    Pending.Resolve(Id);
  }

  #ReceiveAwareness(Values: WireField[]): void {
    const ClientId = StringField(Values, 1);
    if (ClientId === this.#Grant.ClientId) return;
    const Label = StringField(Values, 2);
    const AnchorBytes = OptionalBytesField(Values, 4);
    const HeadBytes = OptionalBytesField(Values, 5);
    const State = NumberField(Values, 6);
    const ColorIndex = NumberField(Values, 7);
    const Remote = this.#RemoteClients.get(ClientId) ?? { AwarenessId: RemoteAwarenessId(ClientId, this.Document.clientID), Clock: 0 };
    Remote.Clock += 1;
    this.#RemoteClients.set(ClientId, Remote);
    const Cursor = AnchorBytes !== undefined && HeadBytes !== undefined && AnchorBytes.byteLength > 0 && HeadBytes.byteLength > 0
      ? { anchor: Y.decodeRelativePosition(AnchorBytes), head: Y.decodeRelativePosition(HeadBytes) }
      : undefined;
    const AwarenessState = State === 3 ? null : {
      ...(Cursor === undefined ? {} : { cursor: Cursor }),
      user: { color: Colors[ColorIndex % Colors.length], name: Label },
    };
    const StateEncoder = Encoding.createEncoder();
    Encoding.writeVarUint(StateEncoder, 1);
    Encoding.writeVarUint(StateEncoder, Remote.AwarenessId);
    Encoding.writeVarUint(StateEncoder, Remote.Clock);
    Encoding.writeVarString(StateEncoder, JSON.stringify(AwarenessState));
    applyAwarenessUpdate(this.Awareness, Encoding.toUint8Array(StateEncoder), RemoteAwarenessOrigin);
    if (State === 3) this.#RemoteClients.delete(ClientId);
  }

  #SendAwareness(State: 1 | 2 | 3): void {
    if (this.#Socket.readyState !== OpenWebSocketState) return;
    const Local = this.Awareness.getLocalState() as Partial<AwarenessLocalState> | null;
    const Anchor = Local?.cursor?.anchor === undefined ? new Uint8Array() : Y.encodeRelativePosition(Y.createRelativePositionFromJSON(Local.cursor.anchor));
    const Head = Local?.cursor?.head === undefined ? new Uint8Array() : Y.encodeRelativePosition(Y.createRelativePositionFromJSON(Local.cursor.head));
    this.#Send(Frame(6, Message([
      Text(1, this.#Grant.ClientId),
      Text(2, this.#Grant.PresenceLabel),
      Unsigned(3, 1),
      Bytes(4, Anchor),
      Bytes(5, Head),
      Unsigned(6, State),
      Unsigned(7, HashUuid(this.#Grant.ClientId) % Colors.length),
    ])));
  }

  #Send(BytesValue: Uint8Array): void {
    if (BytesValue.byteLength > MaximumFrameBytes || this.#Socket.readyState !== OpenWebSocketState) throw new Error("The collaboration transport is unavailable.");
    this.#Socket.send(Uint8Array.from(BytesValue).buffer);
  }

  #Fail(Reason: unknown): void {
    if (this.#Destroyed || this.#Failed) return;
    this.#Failed = true;
    this.#Ready = false;
    if (this.#Heartbeat !== undefined) clearInterval(this.#Heartbeat);
    this.Document.off("update", this.#DocumentUpdate);
    this.Awareness.off("update", this.#AwarenessUpdate);
    this.#PendingCheckpoint?.Reject(Reason);
    this.#PendingCheckpoint = undefined;
    if (this.#Socket.readyState === 0 || this.#Socket.readyState === OpenWebSocketState) this.#Socket.close(4008, "collaboration failed");
    this.#OnStateChange?.("disconnected");
  }
}

/** Language-neutral alias; the wire codec remains the reviewed Yjs codec. */
export { MarkdownRealtimeSession as TextRealtimeSession };

interface ChunkAccumulator {
  Chunks: (Uint8Array | undefined)[];
  Sequence: number;
  Snapshot: boolean;
}

function IsMcpProposalOrigin(Value: unknown): Value is { InvocationId: string; Type: typeof McpProposalOrigin } {
  return typeof Value === "object" && Value !== null
    && (Value as { Type?: unknown }).Type === McpProposalOrigin
    && typeof (Value as { InvocationId?: unknown }).InvocationId === "string";
}

interface WireField {
  Bytes?: Uint8Array;
  Number: number;
  Unsigned?: number;
  Wire: number;
}

function Frame(NumberValue: number, Payload: Uint8Array): Uint8Array {
  return Message([Bytes(NumberValue, Payload)]);
}

function Message(Parts: Uint8Array[]): Uint8Array {
  return Concatenate(Parts);
}

function Text(NumberValue: number, Value: string): Uint8Array {
  return Bytes(NumberValue, Encoder.encode(Value));
}

function Bytes(NumberValue: number, Value: Uint8Array): Uint8Array {
  return Concatenate([Varint(NumberValue * 8 + 2), Varint(Value.byteLength), Value]);
}

function Unsigned(NumberValue: number, Value: number): Uint8Array {
  return Concatenate([Varint(NumberValue * 8), Varint(Value)]);
}

function Varint(Value: number): Uint8Array {
  if (!Number.isSafeInteger(Value) || Value < 0) throw new Error("Invalid protobuf integer.");
  const Result: number[] = [];
  let Remaining = Value;
  do {
    const Byte = Remaining % 128;
    Remaining = Math.floor(Remaining / 128);
    Result.push(Byte + (Remaining > 0 ? 128 : 0));
  } while (Remaining > 0);
  return Uint8Array.from(Result);
}

function Fields(Value: Uint8Array): WireField[] {
  const Result: WireField[] = [];
  let Offset = 0;
  while (Offset < Value.byteLength) {
    const Key = ReadVarint(Value, Offset);
    Offset = Key.Offset;
    const NumberValue = Math.floor(Key.Value / 8);
    const Wire = Key.Value % 8;
    if (NumberValue < 1) throw new Error("Invalid protobuf field.");
    if (Wire === 0) {
      const UnsignedValue = ReadVarint(Value, Offset);
      Offset = UnsignedValue.Offset;
      Result.push({ Number: NumberValue, Unsigned: UnsignedValue.Value, Wire });
    } else if (Wire === 2) {
      const Length = ReadVarint(Value, Offset);
      Offset = Length.Offset;
      const End = Offset + Length.Value;
      if (End > Value.byteLength) throw new Error("Truncated protobuf field.");
      Result.push({ Bytes: Value.slice(Offset, End), Number: NumberValue, Wire });
      Offset = End;
    } else {
      throw new Error("Unsupported protobuf wire type.");
    }
  }
  return Result;
}

function ReadVarint(Value: Uint8Array, Start: number): { Offset: number; Value: number } {
  let Result = 0;
  let Multiplier = 1;
  let Offset = Start;
  for (let Index = 0; Index < 10; Index += 1) {
    const Byte = Value[Offset];
    if (Byte === undefined) throw new Error("Truncated protobuf integer.");
    Offset += 1;
    Result += (Byte & 0x7f) * Multiplier;
    if (!Number.isSafeInteger(Result)) throw new Error("Oversized protobuf integer.");
    if ((Byte & 0x80) === 0) return { Offset, Value: Result };
    Multiplier *= 128;
  }
  throw new Error("Invalid protobuf integer.");
}

function NumberField(Values: WireField[], NumberValue: number): number {
  return Values.find((FieldValue) => FieldValue.Number === NumberValue && FieldValue.Wire === 0)?.Unsigned ?? 0;
}

function BytesField(Values: WireField[], NumberValue: number): Uint8Array {
  return OptionalBytesField(Values, NumberValue) ?? new Uint8Array();
}

function OptionalBytesField(Values: WireField[], NumberValue: number): Uint8Array | undefined {
  return Values.find((FieldValue) => FieldValue.Number === NumberValue && FieldValue.Wire === 2)?.Bytes;
}

function StringField(Values: WireField[], NumberValue: number): string {
  return Decoder.decode(BytesField(Values, NumberValue));
}

function Concatenate(Values: Uint8Array[]): Uint8Array {
  const Length = Values.reduce((Total, Value) => Total + Value.byteLength, 0);
  const Result = new Uint8Array(Length);
  let Offset = 0;
  for (const Value of Values) {
    Result.set(Value, Offset);
    Offset += Value.byteLength;
  }
  return Result;
}

function HashUuid(Value: string): number {
  let Result = 2_166_136_261;
  for (const Byte of Encoder.encode(Value)) Result = Math.imul(Result ^ Byte, 16_777_619) >>> 0;
  return Result;
}

function RemoteAwarenessId(Value: string, LocalId: number): number {
  const Candidate = HashUuid(Value) || 1;
  return Candidate === LocalId ? (Candidate + 1) >>> 0 : Candidate;
}
