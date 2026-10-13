import { createContext, useContext } from "react";

const DraftContext = createContext<{
  drafts: Record<string, string>;
  save: (key: string, value: string) => void;
}>({ drafts: {}, save: () => {} });
export function useDraft(key: string, initial = "") {
  const { drafts, save } = useContext(DraftContext);
  return [drafts[key] ?? initial, (value: string) => save(key, value)] as const;
}
export { DraftContext };

import {
  AlarmClock,
  BellRing,
  BookOpen,
  Bookmark,
  Contact,
  CalendarDays,
  Cpu,
  Folder,
  Globe,
  Home as HomeIcon,
  HousePlug,
  ListTodo,
  Mail,
  MessageSquare,
  Monitor,
  Plug,
  Scissors,
  Settings as SettingsIcon,
  Info as InfoIcon,
  ShieldCheck,
  SquareTerminal,
  StickyNote,
  Store,
  Users,
  Workflow,
  Wrench,
  Activity as ActivityIcon,
} from "lucide-react";

export const FAMILIES = [
  {
    id: "talk",
    title: "Talk",
    links: [
      ["/", "Home", HomeIcon],
      ["/chat", "Chat", MessageSquare],
      ["/inbox", "AI Inbox", BellRing],
    ],
  },
  {
    id: "organize",
    title: "Organize",
    links: [
      ["/notes", "Notes", StickyNote],
      ["/reminders", "Reminders", AlarmClock],
      ["/calendar", "Calendar", CalendarDays],
      ["/contacts", "Contacts", Contact],
      ["/bookmarks", "Bookmarks", Bookmark],
      ["/clips", "Clips", Scissors],
      ["/files", "Files", Folder],
      ["/memory", "Memory", BookOpen],
    ],
  },
  {
    id: "do",
    title: "Do",
    links: [
      ["/tasks", "Tasks", ListTodo],
      ["/approvals", "Approvals", ShieldCheck],
      ["/automations", "Automations", Workflow],
      ["/agents", "Agents", Users],
    ],
  },
  {
    id: "connect",
    title: "Connect",
    links: [
      ["/computers", "Computers", Monitor],
      ["/browser", "Browser", Globe],
      ["/terminal", "Terminal", SquareTerminal],
      ["/home-assistant", "Home Assistant", HousePlug],
      ["/email", "Email", Mail],
      ["/connections", "Connections", Plug],
      ["/models", "Models", Cpu],
      ["/marketplace", "Marketplace", Store],
    ],
  },
  {
    id: "system",
    title: "System",
    links: [
      ["/activity", "Activity", ActivityIcon],
      ["/ops", "Ops", Wrench],
      ["/settings", "Settings", SettingsIcon],
      ["/about", "About", InfoIcon],
    ],
  },
] as const;
