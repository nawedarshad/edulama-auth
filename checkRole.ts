import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
    const email = "demo@gmail.com";
    console.log(`Checking user: ${email}`);

    const user = await prisma.user.findFirst({
        where: { authIdentities: { some: { value: email } } },
        include: {
            authIdentities: true,
            userSchools: {
                include: {
                    school: true,
                    primaryRole: true,
                    roles: { include: { role: true } }
                }
            }
        }
    });

    if (!user) {
        console.log("User not found!");
        return;
    }

    console.log(JSON.stringify(user, null, 2));
}

main().finally(() => prisma.$disconnect());
