import { notFound } from 'next/navigation';

export default function DynamicSegmentsPage({ params }: { params: Promise<{ segments: string[] }> }) {
  notFound();
}