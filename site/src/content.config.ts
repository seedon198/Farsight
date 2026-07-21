import { defineCollection, z } from 'astro:content';
import { glob } from 'astro/loaders';

const docs = defineCollection({
  loader: glob({ pattern: '**/*.md', base: './src/content/docs' }),
  schema: z.object({
    title: z.string(),
    description: z.string(),
    section: z.enum(['Start Here', 'Reference', 'Modules', 'Web UI', 'Help']),
    order: z.number(),
  }),
});

export const collections = { docs };
