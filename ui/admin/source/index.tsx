// SPDX-License-Identifier: Apache-2.0

import { Badge, Button, Input, Tab, TabList } from "@fluentui/react-components";
import { CircleGauge, HardDrive, Plus, ShieldCheck, Users } from "lucide-react";
import { useState } from "react";
import type { FormEvent, ReactNode } from "react";

import { adminEn as strings } from "./strings.js";

export interface AdminUserView {
  email: string;
  id: string;
  name: string;
  status: "active" | "suspended";
}

export interface AdminGroupView {
  id: string;
  managerCount: number;
  memberCount: number;
  name: string;
}

export interface AdminDriveView {
  id: string;
  name: string;
  quotaBytes: number;
  usedBytes: number;
}

export interface AdminPanelProps {
  drives: readonly AdminDriveView[];
  groups: readonly AdminGroupView[];
  onCreateGroup(name: string): Promise<void>;
  onCreateSharedDrive(name: string): Promise<void>;
  onToggleUserSuspension(userId: string): Promise<void>;
  users: readonly AdminUserView[];
}

type AdminTab = "drives" | "groups" | "users";

function formatBytes(value: number): string {
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: 1, notation: "compact", style: "unit", unit: "byte", unitDisplay: "narrow" }).format(value);
}

function Bidi({ children }: { children: string }): ReactNode {
  return <bdi dir="auto">{children}</bdi>;
}

function CreationForm({
  label,
  onCreate,
}: {
  label: string;
  onCreate(value: string): Promise<void>;
}): ReactNode {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (event: FormEvent): Promise<void> => {
    event.preventDefault();
    const trimmed = name.trim();
    if (trimmed.length === 0) return;
    setBusy(true);
    try {
      await onCreate(trimmed);
      setName("");
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="fb-admin-create" onSubmit={(event) => void submit(event)}>
      <Input
        aria-label={label}
        disabled={busy}
        onChange={(_, data) => setName(data.value)}
        placeholder={label}
        value={name}
      />
      <Button appearance="primary" disabled={busy || name.trim().length === 0} icon={<Plus aria-hidden="true" size={20} strokeWidth={1.75} />} type="submit">
        {strings.create}
      </Button>
    </form>
  );
}

export default function AdminPanel({
  drives,
  groups,
  onCreateGroup,
  onCreateSharedDrive,
  onToggleUserSuspension,
  users,
}: AdminPanelProps): ReactNode {
  const [tab, setTab] = useState<AdminTab>("users");
  const [busyUserId, setBusyUserId] = useState<string | null>(null);

  const toggleUser = async (userId: string): Promise<void> => {
    setBusyUserId(userId);
    try {
      await onToggleUserSuspension(userId);
    } finally {
      setBusyUserId(null);
    }
  };

  return (
    <section aria-labelledby="admin-heading" className="fb-admin-page">
      <header className="fb-page-heading">
        <div>
          <p className="fb-eyebrow"><ShieldCheck aria-hidden="true" size={18} strokeWidth={1.75} /> {strings.heading}</p>
          <h1 id="admin-heading">{strings.heading}</h1>
          <p className="fb-muted">{strings.reauth}</p>
        </div>
      </header>

      <TabList aria-label={strings.heading} onTabSelect={(_, data) => setTab(data.value as AdminTab)} selectedValue={tab}>
        <Tab icon={<Users aria-hidden="true" size={20} strokeWidth={1.75} />} value="users">{strings.users}</Tab>
        <Tab icon={<CircleGauge aria-hidden="true" size={20} strokeWidth={1.75} />} value="groups">{strings.groups}</Tab>
        <Tab icon={<HardDrive aria-hidden="true" size={20} strokeWidth={1.75} />} value="drives">{strings.drives}</Tab>
      </TabList>

      {tab === "users" ? (
        <div className="fb-admin-cards" role="list">
          {users.map((user) => (
            <article className="fb-admin-card" key={user.id} role="listitem">
              <div>
                <h2><Bidi>{user.name}</Bidi></h2>
                <p className="fb-muted"><Bidi>{user.email}</Bidi></p>
              </div>
              <Badge appearance="tint" color={user.status === "active" ? "success" : "danger"}>
                {user.status === "active" ? strings.active : strings.suspended}
              </Badge>
              <Button
                appearance={user.status === "active" ? "secondary" : "primary"}
                disabled={busyUserId === user.id}
                onClick={() => void toggleUser(user.id)}
              >
                {user.status === "active" ? strings.suspend : strings.resume}
              </Button>
            </article>
          ))}
        </div>
      ) : null}

      {tab === "groups" ? (
        <div>
          <CreationForm label={strings.createGroup} onCreate={onCreateGroup} />
          <div className="fb-admin-cards" role="list">
            {groups.map((group) => (
              <article className="fb-admin-card" key={group.id} role="listitem">
                <div><h2><Bidi>{group.name}</Bidi></h2></div>
                <dl className="fb-inline-stats">
                  <div><dt>{strings.memberCount}</dt><dd>{group.memberCount}</dd></div>
                  <div><dt>{strings.managerCount}</dt><dd>{group.managerCount}</dd></div>
                </dl>
              </article>
            ))}
          </div>
        </div>
      ) : null}

      {tab === "drives" ? (
        <div>
          <CreationForm label={strings.driveName} onCreate={onCreateSharedDrive} />
          <div className="fb-admin-cards" role="list">
            {drives.map((drive) => (
              <article className="fb-admin-card" key={drive.id} role="listitem">
                <div><h2><Bidi>{drive.name}</Bidi></h2><p className="fb-muted">{strings.quota}: {formatBytes(drive.quotaBytes)}</p></div>
                <div className="fb-quota">
                  <span>{strings.usage}: {formatBytes(drive.usedBytes)}</span>
                  <progress aria-label={`${drive.name} ${strings.usage}`} max={drive.quotaBytes} value={drive.usedBytes} />
                </div>
              </article>
            ))}
          </div>
        </div>
      ) : null}
    </section>
  );
}
